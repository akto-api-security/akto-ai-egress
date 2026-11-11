"""Checks for piece-by-piece guardrails on streamed answers.

Run: python akto-egress-proxy/test_stream_guardrails.py   (needs mitmproxy installed)
Akto is faked: text containing EVIL is blocked, email addresses are masked, the rest is allowed.
"""

import concurrent.futures
import json
import os
import random
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("AKTO_URL", "http://akto.invalid")

import akto_guardrails as g  # noqa: E402
from mitmproxy.test import tflow  # noqa: E402

g.print = lambda *args, **kwargs: None  # the addon logs every payload
EMAIL = re.compile(r"[\w.]+@\w+\.\w{2,}")  # also matches a cut-off "john.doe@acme.co", like a real detector
CALLS = []


def fake_akto(params, payload):
    CALLS.append((params, payload))
    text = payload.get("responsePayload", "")
    if params.get("guardrails") == "true" or params.get("response_guardrails") != "true":
        verdict = {"Allowed": True}
    elif "EVIL" in text:
        verdict = {"Allowed": False, "Reason": "evil content", "Metadata": {"policyName": "test"}}
    elif EMAIL.search(text):
        verdict = {"Allowed": True, "Modified": True, "ModifiedPayload": EMAIL.sub("[EMAIL]", text)}
    else:
        verdict = {"Allowed": True}
    return {"data": {"guardrailsResult": verdict}}


class Inline:
    """Runs each check at once, so tests don't depend on thread timing."""

    def submit(self, fn, *args):
        future = concurrent.futures.Future()
        try:
            future.set_result(fn(*args))
        except Exception as e:
            future.set_exception(e)
        return future


class Deferred:
    """Holds every check until run_all(), so later pieces are sent while earlier ones are still out."""

    def __init__(self):
        self.pending = []

    def submit(self, fn, *args):
        future = concurrent.futures.Future()
        self.pending.append((future, fn, args))
        return future

    def run_all(self):
        for future, fn, args in self.pending:
            future.set_result(fn(*args))
        self.pending = []


g.post_to_akto = fake_akto
g.STREAM_CHECKS = Inline()
g.STREAM_CHUNK_CHARS, g.STREAM_OVERLAP_CHARS = 40, 25


def sse(name, data):
    return (f"event: {name}\n" if name else "") + f"data: {json.dumps(data)}\n\n"


def deltas(text, size=5):
    return [text[i:i + size] for i in range(0, len(text), size)]


def anthropic(text, tool_args=""):
    out = sse("message_start", {"type": "message_start", "message": {"id": "msg_1", "content": []}})
    out += sse("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}})
    out += sse("ping", {"type": "ping"})
    for d in deltas(text):
        out += sse("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": d}})
    out += sse("content_block_stop", {"type": "content_block_stop", "index": 0})
    if tool_args:
        out += sse("content_block_start", {"type": "content_block_start", "index": 1, "content_block": {"type": "tool_use", "id": "t1", "name": "send", "input": {}}})
        for d in deltas(tool_args):
            out += sse("content_block_delta", {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": d}})
        out += sse("content_block_stop", {"type": "content_block_stop", "index": 1})
    out += sse("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn"}})
    out += sse("message_stop", {"type": "message_stop"})
    return out.encode()


def chat(text):
    out = sse(None, {"object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}}]})
    for d in deltas(text):
        out += sse(None, {"object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"content": d}}]})
    out += sse(None, {"object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})
    return (out + "data: [DONE]\n\n").encode()


def responses(text):
    where = {"item_id": "msg_1", "output_index": 0, "content_index": 0}
    item = {"id": "msg_1", "type": "message", "role": "assistant"}
    done_item = {**item, "content": [{"type": "output_text", "text": text}]}
    out = sse("response.created", {"type": "response.created", "response": {"id": "r1", "output": []}})
    out += sse("response.output_item.added", {"type": "response.output_item.added", "output_index": 0, "item": {**item, "content": []}})
    out += sse("response.content_part.added", {"type": "response.content_part.added", **where, "part": {"type": "output_text", "text": ""}})
    for d in deltas(text):
        out += sse("response.output_text.delta", {"type": "response.output_text.delta", **where, "delta": d})
    out += sse("response.output_text.done", {"type": "response.output_text.done", **where, "text": text})
    out += sse("response.content_part.done", {"type": "response.content_part.done", **where, "part": {"type": "output_text", "text": text}})
    out += sse("response.output_item.done", {"type": "response.output_item.done", "output_index": 0, "item": done_item})
    out += sse("response.completed", {"type": "response.completed", "response": {"id": "r1", "output": [done_item]}})
    return out.encode()


STREAMS = [("/v1/messages", anthropic), ("/v1/chat/completions", chat), ("/v1/responses", responses)]


def make_flow(path):
    flow = tflow.tflow(resp=True)
    flow.request.host = "api.anthropic.com"
    flow.request.path = path
    flow.response.headers["content-type"] = "text/event-stream"
    return flow


def run(body, path, size=7):
    """Feed a stream through a StreamGuard in `size`-byte network chunks; return what each call sent on."""
    guard = g.StreamGuard(make_flow(path))
    outs = [guard(body[i:i + size]) for i in range(0, len(body), size)]
    return outs + [guard(b"")]


def events(out):
    return [g.StreamEvent(raw + b"\n\n") for raw in out.split(b"\n\n") if raw.strip()]


def streamed_text(out):
    return "".join(e.text for e in events(out))


def ingests():
    return [payload for params, payload in CALLS if params == {"ingest_data": "true"}]


def test_clean_stream_goes_out_unchanged_and_before_the_end():
    text = "The quick brown fox jumps over the lazy dog. " * 6
    for path, build in STREAMS:
        CALLS.clear()
        body = build(text)
        outs = run(body, path)
        assert b"".join(outs) == body, path
        assert streamed_text(b"".join(outs[:-1])), f"{path}: nothing was forwarded before the stream ended"
        checks = [c for c in CALLS if c[0].get("response_guardrails") == "true"]
        assert len(checks) > 1, f"{path}: answer checked in one go"
        assert all(c[0]["ingest_data"] == "false" for c in checks)
        assert [p["responsePayload"] for p in ingests()] == [body.decode()], f"{path}: not ingested exactly once"


def test_block_mid_stream_sends_the_providers_error_and_nothing_after():
    text = "Safe opening words here. " * 4 + "now the EVIL plan " + "and more words. " * 4
    for path, build in STREAMS:
        CALLS.clear()
        out = b"".join(run(build(text), path))
        assert b"EVIL" not in out, path
        assert streamed_text(out).startswith("Safe opening"), f"{path}: nothing forwarded before the block"
        last = events(out)[-1]
        assert last.name == "error", path
        if path == "/v1/messages":
            assert last.data["error"] == {"type": "permission_error", "message": "evil content", "metadata": {"policyName": "test"}}
        else:
            assert last.data["error"]["message"] == "evil content", path
        assert out.count(b"event: error") == 1, path
        assert len(ingests()) == 1, path


def test_tool_call_arguments_are_checked():
    CALLS.clear()
    out = b"".join(run(anthropic("Sending it now. " * 4, tool_args='{"body": "the EVIL payload"}'), "/v1/messages"))
    assert b"EVIL" not in out
    assert events(out)[-1].name == "error"


def test_email_is_masked_whole_wherever_the_pieces_cut_it():
    for offset in range(80):
        text = ("word " * 20)[:offset] + "mail john.doe@acme.com now " + "tail words " * 8
        for path, build in STREAMS:
            out = b"".join(run(build(text), path))
            assert b"john" not in out, f"{path} offset {offset}: {streamed_text(out)!r}"
            assert streamed_text(out) == EMAIL.sub("[EMAIL]", text), f"{path} offset {offset}: {streamed_text(out)!r}"


def test_email_is_masked_once_when_checks_overlap_in_time():
    """A masked piece can also send part of the next piece's overlap. If the next check was already out,
    its masked text covers that overlap too, so it must be checked again rather than sent twice."""
    for offset in range(80):
        text = ("word " * 20)[:offset] + "mail john.doe@acme.com now " + "tail words " * 8
        for path, build in STREAMS:
            body, deferred = build(text), Deferred()
            g.STREAM_CHECKS = deferred
            try:
                guard = g.StreamGuard(make_flow(path))
                outs = [guard(body[i:i + 7]) for i in range(0, len(body), 7)]
                deferred.run_all()
            finally:
                g.STREAM_CHECKS = Inline()
            outs.append(guard(b""))
            out = b"".join(outs)
            assert streamed_text(out) == EMAIL.sub("[EMAIL]", text), f"{path} offset {offset}: {streamed_text(out)!r}"


def test_responses_done_events_carry_the_masked_text():
    text = "Write to john.doe@acme.com today. " * 3
    out = b"".join(run(responses(text), "/v1/responses"))
    done = {e.data["type"]: e.data for e in events(out) if e.data and e.data["type"].endswith(".done")}
    masked = EMAIL.sub("[EMAIL]", text)
    assert done["response.output_text.done"]["text"] == masked
    assert done["response.content_part.done"]["part"]["text"] == masked
    assert done["response.output_item.done"]["item"]["content"][0]["text"] == masked


def test_slow_stream_is_checked_without_waiting_for_a_full_piece():
    g.STREAM_FLUSH_SECONDS, flush = 0, g.STREAM_FLUSH_SECONDS
    try:
        outs = run(anthropic("Just thirty-five chars of answer!!"), "/v1/messages")
        assert streamed_text(b"".join(outs[:-1])), "a short, slow answer waited for the end"
    finally:
        g.STREAM_FLUSH_SECONDS = flush


def test_failed_checks_let_the_stream_through():
    g.post_to_akto = lambda params, payload: 1 / 0
    try:
        body = anthropic("The quick brown fox jumps over the lazy dog. " * 4)
        assert b"".join(run(body, "/v1/messages")) == body
    finally:
        g.post_to_akto = fake_akto


def test_an_internal_error_passes_the_rest_through_in_order():
    add, seen = g.StreamGuard.add, []

    def flaky_add(self, event, out):
        seen.append(event)
        if len(seen) == 20:
            raise RuntimeError("boom")
        add(self, event, out)

    g.StreamGuard.add = flaky_add
    try:
        body = anthropic("The quick brown fox jumps over the lazy dog. " * 4)
        assert b"".join(run(body, "/v1/messages")) == body
    finally:
        g.StreamGuard.add = add


def test_checks_on_real_threads_keep_order():
    g.STREAM_CHECKS = concurrent.futures.ThreadPoolExecutor(max_workers=8)
    g.post_to_akto = lambda params, payload: (time.sleep(random.uniform(0, 0.01)), fake_akto(params, payload))[1]
    try:
        for path, build in STREAMS:
            text = "Reach john.doe@acme.com or the desk. " * 6
            body = build(text)
            guard = g.StreamGuard(make_flow(path))
            outs = []
            for i in range(0, len(body), 11):
                outs.append(guard(body[i:i + 11]))
                time.sleep(0.001)
            outs.append(guard(b""))
            assert streamed_text(b"".join(outs)) == EMAIL.sub("[EMAIL]", text), path
    finally:
        g.STREAM_CHECKS.shutdown(wait=True)  # its ingest calls would otherwise land in the next test
        g.STREAM_CHECKS = Inline()
        g.post_to_akto = fake_akto


def test_only_known_uncompressed_streams_are_checked_in_pieces():
    addon = g.AktoGuardrailsAddon()

    def streamed(path="/v1/messages", **headers):
        flow = make_flow(path)
        flow.response.headers.update(headers)
        addon.responseheaders(flow)
        return callable(flow.response.stream)

    assert streamed()
    assert streamed("/v1/chat/completions?api-version=1")
    assert not streamed(**{"content-encoding": "gzip"})
    assert not streamed(**{"content-type": "application/json"})
    assert not streamed("/model/x/invoke-with-response-stream")
    g.STREAM_GUARDRAILS = False
    try:
        assert not streamed()
    finally:
        g.STREAM_GUARDRAILS = True


def test_streamed_flows_skip_the_end_of_response_check():
    flow = make_flow("/v1/messages")
    g.AktoGuardrailsAddon().responseheaders(flow)
    CALLS.clear()
    g.AktoGuardrailsAddon().response(flow)
    assert CALLS == []


def test_stream_requests_ask_for_an_uncompressed_answer():
    flow = make_flow("/v1/messages")
    flow.request.text = json.dumps({"stream": True, "messages": []})
    flow.request.headers["Accept-Encoding"] = "gzip, deflate"
    g.AktoGuardrailsAddon().request(flow)
    assert flow.request.headers["Accept-Encoding"] == "identity"


if __name__ == "__main__":
    tests = [(name, fn) for name, fn in sorted(globals().items()) if name.startswith("test_")]
    for name, fn in tests:
        fn()
        print(f"ok  {name}")
    print(f"{len(tests)} passed")
