import asyncio
import json
import os
import time
import zlib

from concurrent.futures import ThreadPoolExecutor

import requests
from mitmproxy import http

AKTO_URL = f"{os.getenv('AKTO_URL')}/api/http-proxy" if os.getenv("AKTO_URL") else None
APP_NAME = os.getenv("APP_NAME")

TEXT_THRESHOLD  = int(os.getenv("AKTO_TEXT_THRESHOLD", "600"))
LOG_PAYLOADS    = os.getenv("AKTO_LOG_PAYLOADS", "").lower() == "true"
_hook_executor   = ThreadPoolExecutor(max_workers=4)   # request/response hook API calls
_stream_executor = ThreadPoolExecutor(max_workers=8)   # stream batch API calls (1 per agent)
_session = requests.Session()                          # shared connection pool to Akto

AI_HOSTS = {
    "api.openai.com",
    "api.anthropic.com",
}

_AGENTIC_TAG = json.dumps({"gen-ai": "Gen AI", "source": "AGENTIC"})
_REQUEST_PARAMS = {"guardrails": "true", "ingest_data": "true"}
_RESPONSE_PARAMS = {"response_guardrails": "true", "ingest_data": "true"}

print(
    f"[AKTO] starting"
    f" | url={AKTO_URL}"
    f" | threshold={TEXT_THRESHOLD} chars"
    f" | log_payloads={LOG_PAYLOADS}"
    f" | hook_workers={_hook_executor._max_workers}"
    f" | stream_workers={_stream_executor._max_workers}"
    f" | stream_timeout=5s"
)

def is_ai_provider(flow: http.HTTPFlow) -> bool:
    return flow.request.pretty_host in AI_HOSTS

def _provider(flow: http.HTTPFlow) -> str:
    return "openai" if "openai" in flow.request.pretty_host else "anthropic"

def _agent_id(flow: http.HTTPFlow) -> str:
    if flow.client_conn.peername:
        return f"{flow.client_conn.peername[0]}:{flow.client_conn.peername[1]}"
    return "unknown"

def safe_headers(headers) -> str:
    return json.dumps(dict(headers))

def minimal_headers(headers) -> str:
    result = {}
    ct = headers.get("content-type", "")
    if ct:
        result["content-type"] = ct
    if APP_NAME:
        result["host"] = APP_NAME
    return json.dumps(result) if result else "{}"

def extract_messages(flow: http.HTTPFlow) -> str:
    try:
        body = flow.request.get_text(strict=False) or ""
        data = json.loads(body)
        if "messages" in data:
            return json.dumps({"messages": data["messages"]})
        return json.dumps({"raw": data})
    except Exception:
        return ""

def build_akto_payload(
    flow: http.HTTPFlow,
    response_body: str = "",
    status_code: str = "200",
) -> dict:
    return {
        "path": flow.request.path,
        "requestHeaders": minimal_headers(flow.request.headers),
        "responseHeaders": safe_headers(flow.response.headers) if flow.response else "{}",
        "method": flow.request.method,
        "requestPayload": extract_messages(flow),
        "responsePayload": response_body,
        "ip": flow.client_conn.peername[0] if flow.client_conn.peername else "127.0.0.1",
        "destIp": flow.server_conn.ip_address[0] if flow.server_conn.ip_address else "127.0.0.1",
        "time": str(int(time.time() * 1000)),
        "statusCode": str(status_code),
        "type": None,
        "status": str(status_code),
        "akto_account_id": "1000000",
        "akto_vxlan_id": "test",
        "is_pending": "false",
        "source": "MIRRORING",
        "direction": None,
        "process_id": None,
        "socket_id": None,
        "daemonset_id": None,
        "enabled_graph": None,
        "tag": _AGENTIC_TAG,
        "metadata": _AGENTIC_TAG,
        "contextSource": "AGENTIC",
    }

def _call_akto_sync(payload: dict, params: dict, label: str = "payload", timeout: int = 15) -> dict:
    if LOG_PAYLOADS:
        print(f"[AKTO] {label} | {payload}")
    t0 = time.time()
    r = _session.get(
        AKTO_URL,
        params=params,
        headers={"Content-Type": "application/json"},
        json=payload,
        timeout=timeout,
    )
    r.raise_for_status()
    result = r.json()
    latency_ms = (time.time() - t0) * 1000
    check_type = label.replace(" payload", "")
    if LOG_PAYLOADS:
        print(f"[AKTO] response | {check_type} | latency={latency_ms:.0f}ms | {result}")
    else:
        print(f"[AKTO] response | {check_type} | latency={latency_ms:.0f}ms")
    return result

async def _call_akto(payload: dict, params: dict, label: str = "payload") -> dict:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_hook_executor, lambda: _call_akto_sync(payload, params, label))

async def call_akto_request(flow: http.HTTPFlow) -> dict:
    print(f"[AKTO] REQUEST  | agent={_agent_id(flow)} | {flow.request.method} {flow.request.pretty_host}{flow.request.path}")
    return await _call_akto(build_akto_payload(flow), _REQUEST_PARAMS, label="request payload")

def call_akto_response_stream(flow: http.HTTPFlow, text_chunk: str) -> dict:
    # sync — called from _stream_executor in the stream handler
    print(f"[AKTO] STREAM   | agent={_agent_id(flow)} | {len(text_chunk)} chars | [{text_chunk}]")
    response_body = json.dumps({"content": [{"type": "text", "text": text_chunk}]})
    return _call_akto_sync(
        build_akto_payload(flow, response_body=response_body, status_code=str(flow.response.status_code)),
        _RESPONSE_PARAMS,
        label="stream payload",
        timeout=5,
    )

async def call_akto_response(flow: http.HTTPFlow) -> dict:
    print(f"[AKTO] RESPONSE | agent={_agent_id(flow)} | {flow.request.method} {flow.request.pretty_host}{flow.request.path}")
    return await _call_akto(
        build_akto_payload(flow, response_body=flow.response.get_text(strict=False) or "", status_code=str(flow.response.status_code)),
        _RESPONSE_PARAMS,
        label="response payload",
    )

def _get_guardrails_result(result: dict) -> dict:
    return result.get("data", {}).get("guardrailsResult", {})

def get_request_result(result: dict) -> dict:
    gr = _get_guardrails_result(result)
    # handles both schema variants: requestResult nested or flat
    return gr.get("requestResult", gr)

def get_response_result(result: dict) -> dict:
    return _get_guardrails_result(result)


def _apply_guardrail_check(flow: http.HTTPFlow, check: dict, context: str, target) -> bool:
    """Apply guardrail result to flow. Returns True if the request/response was blocked."""
    behaviour = (check.get("behaviour") or "").lower()
    reason = check.get("Reason") or f"Blocked by Akto {context} guardrails"

    if behaviour == "block":
        print(f"[AKTO] {context.upper()} | decision=BLOCKED | {reason}")
        flow.response = http.Response.make(
            403,
            json.dumps({"error": reason}),
            {"Content-Type": "application/json", "X-Akto-Guardrails-Decision": "blocked"},
        )
        return True

    if check.get("Allowed") is not True:
        print(f"[AKTO] {context.upper()} | alert | behaviour={behaviour or 'none'} | {reason}")

    if check.get("Modified") is True and check.get("ModifiedPayload"):
        target.set_text(check["ModifiedPayload"])

    return False

def extract_sse_events(raw: bytes) -> tuple:
    """
    Split raw bytes into complete SSE events (delimited by \\n\\n) and a leftover
    incomplete tail. Also extracts text content from Anthropic and OpenAI delta events.
    Returns: (complete_event_bytes, leftover_bytes, extracted_text)
    """
    parts = raw.split(b"\n\n")
    complete_parts = parts[:-1]   # everything before the last \n\n is a complete event
    leftover = parts[-1]          # last part may be incomplete

    extracted_text = ""
    for part in complete_parts:
        for line in part.split(b"\n"):
            if not line.startswith(b"data: "):
                continue
            data = line[6:]
            if data.strip() == b"[DONE]":
                continue
            try:
                obj = json.loads(data)
                delta = obj.get("delta", {})
                delta_type = delta.get("type")

                if delta_type == "text_delta":
                    extracted_text += delta.get("text", "")
                elif delta_type == "input_json_delta":
                    extracted_text += delta.get("partial_json", "")

                if obj.get("type") == "content_block_start":
                    block = obj.get("content_block", {})
                    if block.get("type") == "tool_use":
                        extracted_text += f"[tool:{block.get('name', '')}]"

                for choice in obj.get("choices", []):
                    extracted_text += choice.get("delta", {}).get("content", "") or ""
            except (json.JSONDecodeError, AttributeError):
                pass

    complete_bytes = b"\n\n".join(complete_parts)
    if complete_parts:
        complete_bytes += b"\n\n"

    return complete_bytes, leftover, extracted_text

class AktoGuardrailsAddon:
    def responseheaders(self, flow: http.HTTPFlow):
        if not is_ai_provider(flow):
            return
        content_type = flow.response.headers.get("content-type", "")
        if "text/event-stream" not in content_type:
            return
        content_encoding = flow.response.headers.get("content-encoding", "").lower()
        is_gzip = "gzip" in content_encoding
        flow.metadata["_akto_streaming"] = True
        flow.metadata["_akto_gzip"] = is_gzip
        if is_gzip:
            del flow.response.headers["content-encoding"]
        flow.response.stream = self._make_stream_handler(flow)

    def _make_stream_handler(self, flow: http.HTTPFlow):
        state = {
            "batch_bytes": b"",    # raw bytes for the batch currently accumulating
            "batch_text": "",      # extracted text for the batch currently accumulating
            "decode_buffer": b"",  # SSE parse window
            "inflight": None,      # {"future": Future, "bytes": bytes} for the in-flight API call
            "anything_sent": False, # True once any bytes have been yielded to the client
            "decompressor": (
                zlib.decompressobj(16 + zlib.MAX_WBITS)
                if flow.metadata.get("_akto_gzip")
                else None
            ),
        }

        def _block_event(reason: str) -> bytes:
            return f'data: {json.dumps({"error": reason})}\n\ndata: [DONE]\n\n'.encode()

        def _wait_inflight():
            """Wait for the in-flight API result. Returns (approved_bytes, block_reason)."""
            entry = state["inflight"]
            state["inflight"] = None
            t_wait = time.time()
            try:
                result = entry["future"].result()
                waited_ms = (time.time() - t_wait) * 1000
                pipeline_ok = "pipeline ok" if waited_ms < 50 else f"waited {waited_ms:.0f}ms"
                check = get_response_result(result)
                behaviour = (check.get("behaviour") or "").lower()
                if behaviour == "block":
                    print(f"[AKTO] STREAM   | agent={_agent_id(flow)} | collecting result | {pipeline_ok}")
                    return b"", check.get("Reason") or "Blocked by Akto response guardrails"
                if check.get("Allowed") is not True:
                    print(f"[AKTO] STREAM   | agent={_agent_id(flow)} | alert | {pipeline_ok} | {check.get('Reason', '')}")
                else:
                    print(f"[AKTO] STREAM   | agent={_agent_id(flow)} | collecting result | {pipeline_ok}")
            except Exception as e:
                print(f"[AKTO] STREAM   | error (fail open) | {e}")
            return entry["bytes"], None

        def stream_handler(chunk: bytes):
            is_end = not chunk

            if not is_end:
                if state["decompressor"]:
                    try:
                        decoded = state["decompressor"].decompress(chunk)
                    except zlib.error as e:
                        print(f"[AKTO] decompression error (using raw): {e}")
                        decoded = chunk
                else:
                    decoded = chunk

                state["batch_bytes"] += decoded
                state["decode_buffer"] += decoded
                _, leftover, chunk_text = extract_sse_events(state["decode_buffer"])
                state["decode_buffer"] = leftover
                state["batch_text"] += chunk_text

            should_flush = (
                len(state["batch_text"]) >= TEXT_THRESHOLD
                or (is_end and (state["batch_bytes"] or state["inflight"]))
            )

            if not should_flush:
                return

            # Step 1: collect result from the previous batch's in-flight API call
            if state["inflight"]:
                approved_bytes, block_reason = _wait_inflight()
                if block_reason:
                    print(f"[AKTO] STREAM   | agent={_agent_id(flow)} | decision=BLOCKED | {block_reason}")
                    state["batch_bytes"] = b""
                    state["batch_text"] = ""
                    yield _block_event(block_reason)
                    return
                state["anything_sent"] = True
                yield approved_bytes

            # Step 2: fire API call for the current batch in the background
            if state["batch_text"]:
                print(f"[AKTO] STREAM   | agent={_agent_id(flow)} | firing async | {len(state['batch_text'])} chars")
                state["inflight"] = {
                    "future": _stream_executor.submit(call_akto_response_stream, flow, state["batch_text"]),
                    "bytes": state["batch_bytes"],
                }
                state["batch_bytes"] = b""
                state["batch_text"] = ""
            elif state["batch_bytes"]:
                # No text content (pure metadata SSE events) — forward directly, no guardrail needed
                state["anything_sent"] = True
                yield state["batch_bytes"]
                state["batch_bytes"] = b""

            # Step 3: on stream end, drain the final in-flight batch
            if is_end and state["inflight"]:
                approved_bytes, block_reason = _wait_inflight()
                if block_reason:
                    print(f"[AKTO] STREAM   | agent={_agent_id(flow)} | decision=BLOCKED | {block_reason}")
                    yield _block_event(block_reason)
                    return
                state["anything_sent"] = True
                yield approved_bytes

        return stream_handler

    async def request(self, flow: http.HTTPFlow):
        if not is_ai_provider(flow):
            return
        try:
            check = get_request_result(await call_akto_request(flow))
            _apply_guardrail_check(flow, check, "request", flow.request)
        except Exception as e:
            print(f"[AKTO] REQUEST  | error (fail open) | {e}")

    async def response(self, flow: http.HTTPFlow):
        if not is_ai_provider(flow):
            return
        if flow.metadata.get("_akto_streaming"):
            return
        if flow.response.headers.get("X-Akto-Guardrails-Decision") == "blocked":
            return
        try:
            check = get_response_result(await call_akto_response(flow))
            _apply_guardrail_check(flow, check, "response", flow.response)
        except Exception as e:
            print(f"[AKTO] RESPONSE | error (fail open) | {e}")

addons = [AktoGuardrailsAddon()]
