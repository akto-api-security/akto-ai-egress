import collections
import concurrent.futures
import json
import re
import time
import requests
from mitmproxy import ctx, http

import os

AKTO_URL = f"{os.getenv('AKTO_URL')}/api/http-proxy" if os.getenv("AKTO_URL") else None
AKTO_ENABLED = bool(AKTO_URL)
APP_NAME = os.getenv("APP_NAME")
# Bare JWT (no "Bearer " prefix) — required when data-ingestion runs with authentication on.
AKTO_TOKEN = os.getenv("AKTO_TOKEN")

# Comma-separated hostnames; "*" matches any run of characters.
DEFAULT_AI_HOSTS = ",".join([
    "api.openai.com",
    "api.anthropic.com",
    "chatgpt.com",
    "bedrock-runtime.*.amazonaws.com",
    "bedrock-agent-runtime.*.amazonaws.com",
])
AI_HOSTS = [h.strip().lower() for h in (os.getenv("AI_HOSTS") or DEFAULT_AI_HOSTS).split(",") if h.strip()]

# Comma-separated key=value pairs added to the tag sent to Akto, e.g. "env=prod,team=payments".
# The default gen-ai/source tags always win so Akto keeps classifying the traffic as agentic.
DEFAULT_TAGS = {"gen-ai": "Gen AI", "source": "AGENTIC"}
CUSTOM_TAGS = {}
for pair in (os.getenv("AKTO_TAGS") or "").split(","):
    key, sep, value = pair.partition("=")
    if sep and key.strip():
        CUSTOM_TAGS[key.strip()] = value.strip()
    elif pair.strip():
        print(f"[AKTO] ignoring malformed AKTO_TAGS entry: {pair.strip()!r}")
TAGS = json.dumps({**CUSTOM_TAGS, **DEFAULT_TAGS})

AI_HOSTS_PATTERN ="|".join(re.escape(h).replace(r"\*", r"[^:]*") for h in AI_HOSTS)
AI_HOSTS_RE = re.compile(rf"^(?:{AI_HOSTS_PATTERN})$", re.IGNORECASE)
# mitmproxy matches allow_hosts against "host:port", not the bare hostname.
ALLOW_HOSTS_REGEX = rf"^(?:{AI_HOSTS_PATTERN}):\d+$"

print(f"[AKTO] URL: {AKTO_URL}")
print(f"[AKTO] AI hosts: {AI_HOSTS}")
print(f"[AKTO] tags: {TAGS}")

def is_ai_provider(flow: http.HTTPFlow) -> bool:
    return bool(AI_HOSTS_RE.match(flow.request.pretty_host))


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

        # fallback if structure changes
        return json.dumps({"raw": data})

    except Exception:
        return ""

def apply_masked_request(flow: http.HTTPFlow, modified_payload: str) -> None:
    # Akto masks the payload extract_messages sent ({"messages": ...} or {"raw": ...}), not the
    # provider body. Put the masked messages back into the original body so provider fields
    # such as model and max_tokens survive; replacing the whole body would drop them.
    try:
        masked = json.loads(modified_payload)
        if "messages" in masked:
            body = json.loads(flow.request.get_text(strict=False) or "")
            body["messages"] = masked["messages"]
            flow.request.set_text(json.dumps(body))
            return
        if "raw" in masked:
            flow.request.set_text(json.dumps(masked["raw"]))
            return
    except Exception as e:
        print(f"[AKTO] could not merge masked request into body, replacing it: {e}")
    flow.request.set_text(modified_payload)

def build_akto_payload(
    flow: http.HTTPFlow,
    response_body: str = "",
    status_code: str = "200",
) -> dict:
    xx = {
        "path": flow.request.path,
        "requestHeaders": minimal_headers(flow.request.headers),
        "responseHeaders": safe_headers(flow.response.headers) if flow.response else "{}",
        "method": flow.request.method,
        "requestPayload": extract_messages(flow),
        "responsePayload": response_body,
        "ip": flow.metadata.get("akto_client_ip") or (flow.client_conn.peername[0] if flow.client_conn.peername else "127.0.0.1"),
        "destIp": flow.server_conn.ip_address[0] if flow.server_conn.ip_address else "127.0.0.1",
        "time": str(int(time.time() * 1000)),
        "statusCode": str(status_code),
        "type": None,
        "status": str(status_code),
        "akto_account_id": "1000000",
        "akto_vxlan_id": "0",
        "is_pending": "false",
        "source": "MIRRORING",
        "direction": None,
        "process_id": None,
        "socket_id": None,
        "daemonset_id": None,
        "enabled_graph": None,
        "tag": TAGS,
        "metadata": json.dumps({"gen-ai": "Gen AI", "source": "AGENTIC"}),
        "contextSource": "AGENTIC",
    }
    print("payload", xx)
    return xx


def post_to_akto(params: dict, payload: dict) -> dict:
    headers = {"Content-Type": "application/json"}
    if AKTO_TOKEN:
        headers["Authorization"] = AKTO_TOKEN
    r = requests.post(AKTO_URL, params=params, headers=headers, json=payload, timeout=15)
    r.raise_for_status()
    return r.json()


def call_akto_request(flow: http.HTTPFlow) -> dict:
    print ("evaluating request: ")
    return post_to_akto(
        {"guardrails": "true", "ingest_data": "true"},
        build_akto_payload(flow),
    )


def call_akto_response(flow: http.HTTPFlow) -> dict:
    print("evaluating response: ")
    return post_to_akto(
        {"response_guardrails": "true", "ingest_data": "true"},
        build_akto_payload(
            flow,
            response_body=flow.response.get_text(strict=False) or "",
            status_code=str(flow.response.status_code),
        ),
    )


def get_request_result(result: dict) -> dict:
    guardrails_result = (
        result
        .get("data", {})
        .get("guardrailsResult", {})
    )

    # Schema 1: request guardrails nested under requestResult
    if "requestResult" in guardrails_result:
        return guardrails_result.get("requestResult", {})

    # Schema 2: request guardrails directly under guardrailsResult
    return guardrails_result

def get_response_result(result: dict) -> dict:
    print(json.dumps(result))
    return result.get("data", {}).get("guardrailsResult", {})


def response_verdict(check: dict) -> tuple:
    """(blocked, masked payload or "", reason, metadata) from a response guardrails result."""
    blocked = check.get("Allowed") is not True or check.get("behaviour") == "block"
    masked = (check.get("ModifiedPayload") or "") if check.get("Modified") is True else ""
    reason = check.get("Reason") or "Blocked by Akto response guardrails"
    return blocked, masked, reason, check.get("Metadata", {})


def block_response(reason: str, metadata=None, status_code: int = 403):
    return http.Response.make(
        status_code,
        json.dumps({
            "error": reason,
            "metadata": metadata or {},
        }),
        {"Content-Type": "application/json", "X-Akto-Guardrails-Decision": "blocked"},
    )


# Streamed answers are checked piece by piece as they arrive, and each piece is forwarded once it passes.
# On unless "false"; "false" restores holding the whole stream and checking it once at the end.
STREAM_GUARDRAILS = (os.getenv("AKTO_STREAM_GUARDRAILS") or "").strip().lower() != "false"
# Characters of model text per check: smaller pieces start flowing sooner but cost more guardrail calls.
STREAM_CHUNK_CHARS = int(os.getenv("AKTO_STREAM_CHUNK_CHARS") or 300)
# The end of each piece is held back and checked again with the next piece, so a phrase or value split
# across two pieces is still seen, and masked, whole.
STREAM_OVERLAP_CHARS = 100
# A slow stream checks what it has after this long instead of waiting for a full piece.
STREAM_FLUSH_SECONDS = 1.0
# Streams whose events are understood: Anthropic Messages, OpenAI Chat Completions and Responses. Other
# streams (Bedrock's binary event stream, chatgpt.com) are still held and checked whole.
STREAM_PATH_RE = re.compile(r"/(messages|chat/completions|responses)$")
STREAM_CHECKS = concurrent.futures.ThreadPoolExecutor(thread_name_prefix="akto-stream")
SSE_EVENT_END = re.compile(rb"\r\n\r\n|\n\n|\r\r")
ANTHROPIC_TEXT_FIELDS = {"text_delta": "text", "thinking_delta": "thinking", "input_json_delta": "partial_json"}


def wants_stream(flow: http.HTTPFlow) -> bool:
    try:
        return json.loads(flow.request.get_text(strict=False) or "{}").get("stream") is True
    except Exception:
        return False


def is_checkable_stream(flow: http.HTTPFlow) -> bool:
    headers = flow.response.headers
    return (
        "text/event-stream" in headers.get("content-type", "").lower()
        and headers.get("content-encoding", "identity").lower() == "identity"
        and bool(STREAM_PATH_RE.search(flow.request.path.split("?", 1)[0]))
    )


def text_slots(data) -> list:
    """The model-written strings in one stream event, as (content block, text, container, field)."""
    if not isinstance(data, dict):
        return []
    kind = str(data.get("type") or "")
    if kind == "content_block_delta":  # Anthropic: text, thinking, tool-call arguments
        delta = data.get("delta") or {}
        field = ANTHROPIC_TEXT_FIELDS.get(delta.get("type"))
        if field and isinstance(delta.get(field), str):
            return [(("anthropic", data.get("index")), delta[field], delta, field)]
        return []
    if kind.endswith(".delta") and kind != "response.audio.delta" and isinstance(data.get("delta"), str):
        # OpenAI Responses: output text, refusals, reasoning, tool-call arguments
        block = ("responses", kind, data.get("item_id"), data.get("output_index"), data.get("content_index"), data.get("summary_index"))
        return [(block, data["delta"], data, "delta")]
    slots = []
    for choice in data.get("choices") or []:  # OpenAI Chat Completions
        delta = choice.get("delta") or {}
        for field in ("content", "refusal", "reasoning_content", "reasoning"):
            if isinstance(delta.get(field), str) and delta[field]:
                slots.append((("chat", choice.get("index"), field), delta[field], delta, field))
        for call in delta.get("tool_calls") or []:
            function = call.get("function") or {}
            if isinstance(function.get("arguments"), str) and function["arguments"]:
                slots.append((("chat", choice.get("index"), "tool", call.get("index")), function["arguments"], function, "arguments"))
    return slots


def replace_strings(node, replacements: dict) -> bool:
    """Swap every string value equal to a key of `replacements`, anywhere in `node`. True if any changed."""
    changed = False
    items = node.items() if isinstance(node, dict) else enumerate(node) if isinstance(node, list) else ()
    for key, value in list(items):
        if isinstance(value, str) and value in replacements:
            node[key] = replacements[value]
            changed = True
        elif isinstance(value, (dict, list)):
            changed = replace_strings(value, replacements) or changed
    return changed


def stream_block_event(dialect: str, reason: str, metadata) -> bytes:
    """The provider's own mid-stream error event, so the client SDK raises as it does for a blocked call."""
    if dialect == "openai":
        # The OpenAI SDK raises only when the event carries an "error" object (Chat Completions and Responses).
        error = {"message": reason, "type": "guardrails_blocked", "code": "guardrails_blocked", "metadata": metadata or {}}
        body = {"type": "error", "message": reason, "code": "guardrails_blocked", "param": None, "error": error}
    else:
        body = {"type": "error", "error": {"type": "permission_error", "message": reason, "metadata": metadata or {}}}
    return b"event: error\ndata: " + json.dumps(body).encode() + b"\n\n"


class StreamEvent:
    """One server-sent event, with the model-written text it carries."""

    def __init__(self, raw: bytes):
        self.raw = raw
        self.name = None
        self.data = None
        lines = []
        for line in raw.decode("utf-8", "replace").splitlines():
            field, _, value = line.partition(":")
            value = value[1:] if value.startswith(" ") else value
            if field == "event":
                self.name = value
            elif field == "data":
                lines.append(value)
        try:
            self.data = json.loads("\n".join(lines))
        except ValueError:
            pass
        self.slots = text_slots(self.data)
        self.block = tuple(slot[0] for slot in self.slots) or None
        self.text = "".join(slot[1] for slot in self.slots)
        self.released = False

    def with_text(self, text: str) -> bytes:
        for i, (_, _, container, field) in enumerate(self.slots):
            container[field] = text if i == 0 else ""
        return self.serialize()

    def serialize(self) -> bytes:
        name = f"event: {self.name}\n" if self.name else ""
        return f"{name}data: {json.dumps(self.data)}\n\n".encode()


class StreamCheck:
    """Stream events sent to Akto as one guardrail check."""

    def __init__(self, events: list, release_count: int, checked: list, future):
        self.events = events
        # events[:release_count] go out when the check passes; the rest are the overlap, which goes out
        # with the next check.
        self.release_count = release_count
        self.checked = checked  # the events whose text was sent
        self.future = future


class StreamGuard:
    """mitmproxy stream callback for one streamed answer.

    Collects the answer into pieces of about STREAM_CHUNK_CHARS characters, checks each piece with Akto on
    a background thread, and forwards the pieces in order as each check passes. While one piece is being
    checked the next keeps filling, so the stream runs about one check behind, not one per piece.
    """

    def __init__(self, flow: http.HTTPFlow):
        self.payload = build_akto_payload(flow, status_code=str(flow.response.status_code))
        self.dialect = "anthropic"
        self.raw = bytearray()      # everything upstream sent, ingested once at the end
        self.partial = b""          # an event that has not fully arrived yet
        self.window = []            # events not yet in a check
        self.window_block = None    # the content block the window's text belongs to
        self.window_new = 0         # characters added since the last check; the overlap doesn't count
        self.window_since = None    # when that new text started
        self.checks = collections.deque()
        self.original = collections.defaultdict(str)   # per content block: the text upstream sent
        self.forwarded = collections.defaultdict(str)  # per content block: the text sent on, after masking
        self.masked_blocks = set()
        self.state = "checking"     # "blocked": drop the rest; "open": checking failed, pass the rest through
        self.ingested = False

    def __call__(self, data: bytes) -> bytes:
        end = data == b""
        if self.state == "blocked":
            return b""
        self.raw += data
        if self.state == "open":
            if end:
                self.ingest()
            return data
        out, batch = [], []
        try:
            batch = self.split_events(data, end)
            for event in batch:
                self.add(event, out)
            if end:
                self.close_window(keep_overlap=False)
            elif (self.window_since and time.monotonic() - self.window_since >= STREAM_FLUSH_SECONDS
                  and self.window_new > STREAM_OVERLAP_CHARS):
                self.close_window(keep_overlap=True)
            # ponytail: at end of stream this waits for the last checks on mitmproxy's event loop (about one
            # guardrail call per stream); the stream callback has no async way to send the final bytes later.
            self.forward_checked(out, wait=end)
        except Exception as e:
            print(f"[AKTO] stream guardrails failed, passing the rest of the stream through unchecked: {e}")
            self.state = "open"
            for event in self.held() + batch:
                if not event.released:
                    event.released = True
                    out.append(event.raw)
            out.append(self.partial)
            self.partial = b""
        if end:
            self.ingest()
        return b"".join(out)

    def split_events(self, data: bytes, end: bool) -> list:
        self.partial += data
        events = []
        while match := SSE_EVENT_END.search(self.partial):
            events.append(StreamEvent(self.partial[:match.end()]))
            self.partial = self.partial[match.end():]
        if end and self.partial:
            events.append(StreamEvent(self.partial))
            self.partial = b""
        return events

    def add(self, event: StreamEvent, out: list) -> None:
        if isinstance(event.data, dict):
            if "choices" in event.data or str(event.data.get("type") or "").startswith("response."):
                self.dialect = "openai"
        if event.block is None:
            if self.checks or self.window_has_text():
                self.window.append(event)  # stays behind text that is still being checked
            else:
                self.forward(event, out)
            return
        self.original[event.block] += event.text
        if self.window_block not in (None, event.block) and self.window_has_text():
            self.close_window(keep_overlap=False)  # a new content block; no overlap across blocks
        self.window_block = event.block
        self.window.append(event)
        self.window_new += len(event.text)
        self.window_since = self.window_since or time.monotonic()
        if self.window_new >= STREAM_CHUNK_CHARS:
            self.close_window(keep_overlap=True)

    def window_has_text(self) -> bool:
        return any(e.block is not None and not e.released for e in self.window)

    def close_window(self, keep_overlap: bool) -> None:
        checked = [e for e in self.window if e.block is not None and not e.released]
        if not checked:
            return
        split = len(self.window)
        if keep_overlap:
            split, chars = 0, 0
            for i in range(len(self.window) - 1, 0, -1):
                chars += len(self.window[i].text)
                if chars >= STREAM_OVERLAP_CHARS:
                    split = i
                    break
            if split == 0:
                return  # too little text to hold an overlap back and still forward something
        future = STREAM_CHECKS.submit(self.check, "".join(e.text for e in checked))
        self.checks.append(StreamCheck(self.window, split, checked, future))
        self.window = self.window[split:]
        self.window_new = 0
        self.window_since = None
        if not keep_overlap:
            self.window_block = None

    def check(self, text: str) -> dict:
        payload = {**self.payload, "responsePayload": text, "time": str(int(time.time() * 1000))}
        return get_response_result(post_to_akto({"response_guardrails": "true", "ingest_data": "false"}, payload))

    def forward_checked(self, out: list, wait: bool) -> None:
        while self.checks:
            piece = self.checks[0]
            if not wait and not piece.future.done():
                return
            try:
                blocked, masked, reason, metadata = response_verdict(piece.future.result())
            except Exception as e:
                print(f"[AKTO] stream guardrails call failed, allowing this piece: {e}")
                blocked, masked, reason, metadata = False, "", "", {}
            if blocked:
                out.append(stream_block_event(self.dialect, reason, metadata))
                self.state = "blocked"
                self.checks.clear()
                self.window = []
                self.ingest()
                return
            if masked and any(e.released for e in piece.checked):
                # The previous piece was masked and already sent this piece's overlap, so the masked text
                # also covers that overlap. Check the rest again on its own.
                piece.checked = [e for e in piece.checked if not e.released]
                if piece.checked:
                    piece.future = STREAM_CHECKS.submit(self.check, "".join(e.text for e in piece.checked))
                    continue
                masked = ""
            if masked == "".join(e.text for e in piece.checked):
                masked = ""
            if masked and piece.release_count < len(piece.events):  # closed mid-block, with an overlap held back
                if not self.forward_masked_prefix(piece, masked, out):
                    self.merge_into_next(piece)
                    continue
            elif masked:
                self.forward_masked(piece, len(piece.events), masked, out)
            else:
                for event in piece.events[:piece.release_count]:
                    self.forward(event, out)
            self.checks.popleft()
        if not self.window_has_text():
            for event in self.window:
                self.forward(event, out)
            self.window = []

    def forward_masked(self, piece: StreamCheck, count: int, masked: str, out: list) -> None:
        """Send piece.events[:count] with their text replaced by `masked`. Masked text can't be split back
        across the original events, so the first one carries all of it and the rest go out empty."""
        self.masked_blocks.add(piece.checked[0].block)
        first = True
        for event in piece.events[:count]:
            if event in piece.checked:
                self.forward(event, out, masked if first else "")
                first = False
            else:
                self.forward(event, out)

    def forward_masked_prefix(self, piece: StreamCheck, masked: str, out: list) -> bool:
        """Send the part of a masked piece after which masking changed nothing; hold the rest back for the
        next check. False when masking runs to the very end, where a value may go on into text not here yet."""
        text = "".join(e.text for e in piece.checked)
        limit = min(len(text), len(masked)) - len(os.path.commonprefix([text, masked]))
        same = 0
        while same < limit and text[-1 - same] == masked[-1 - same]:
            same += 1
        if same == 0:
            return False
        normal = sum(len(e.text) for e in piece.events[:piece.release_count] if e in piece.checked)
        goal = max(len(text) - same, normal)
        count, pos = 0, 0
        for count, event in enumerate(piece.events, 1):
            pos += len(event.text) if event in piece.checked else 0
            if pos >= goal and count >= piece.release_count:  # events before the overlap exist only here
                break
        self.forward_masked(piece, count, masked[:len(masked) - (len(text) - pos)], out)
        return True

    def merge_into_next(self, piece: StreamCheck) -> None:
        """Check a piece again together with the next one, which already starts with its overlap."""
        self.checks.popleft()
        lead = [e for e in piece.events[:piece.release_count] if not e.released]
        if not self.checks:
            self.window = lead + self.window
            return
        following = self.checks[0]
        following.events = lead + following.events
        following.release_count += len(lead)
        following.checked = [e for e in following.events if e.block is not None and not e.released]
        following.future = STREAM_CHECKS.submit(self.check, "".join(e.text for e in following.checked))

    def forward(self, event: StreamEvent, out: list, text=None) -> None:
        """Send one event on. `text` replaces the model text it carries (masking)."""
        if event.released:
            return
        event.released = True
        if event.block is not None:
            self.forwarded[event.block] += event.text if text is None else text
            out.append(event.raw if text is None or text == event.text else event.with_text(text))
            return
        # Events like OpenAI's response.output_text.done repeat a block's full text: send the masked version.
        masked = {self.original[b]: self.forwarded[b] for b in self.masked_blocks if self.original[b] != self.forwarded[b]}
        out.append(event.serialize() if masked and replace_strings(event.data, masked) else event.raw)

    def held(self) -> list:
        """Events not sent on yet, in stream order (the overlap sits in two places, so skip repeats)."""
        seen, held = set(), []
        for event in [e for piece in self.checks for e in piece.events] + self.window:
            if not event.released and id(event) not in seen:
                seen.add(id(event))
                held.append(event)
        return held

    def ingest(self) -> None:
        if self.ingested:
            return
        self.ingested = True
        payload = {**self.payload, "responsePayload": self.raw.decode("utf-8", "replace"), "time": str(int(time.time() * 1000))}
        STREAM_CHECKS.submit(ingest_stream, payload)


def ingest_stream(payload: dict) -> None:
    try:
        post_to_akto({"ingest_data": "true"}, payload)
    except Exception as e:
        print(f"[AKTO] ingesting the streamed response failed: {e}")


class AktoGuardrailsAddon:
    def load(self, loader):
        # Only decrypt TLS to AI hosts; everything else is tunnelled untouched.
        # An explicit --allow-hosts on the command line wins; --ignore-hosts is
        # applied on top of this to carve out exceptions.
        if not ctx.options.allow_hosts:
            ctx.options.allow_hosts = [ALLOW_HOSTS_REGEX]
        print(f"[AKTO] allow_hosts: {ctx.options.allow_hosts}")
        print(f"[AKTO] ignore_hosts: {ctx.options.ignore_hosts}")

    def request(self, flow: http.HTTPFlow):
        if not is_ai_provider(flow):
            return

        # The agent passes its caller's IP in X-Forwarded-For; keep the first
        # (originating) entry for Akto and strip it so it never reaches the LLM.
        forwarded_for = flow.request.headers.pop("X-Forwarded-For", "")
        client_ip = forwarded_for.split(",")[0].strip()
        if client_ip:
            flow.metadata["akto_client_ip"] = client_ip

        if STREAM_GUARDRAILS and wants_stream(flow):
            # A compressed stream can't be read piece by piece, so ask for it uncompressed.
            flow.request.headers["Accept-Encoding"] = "identity"

        try:
            result = call_akto_request(flow)
            check = get_request_result(result)
            allowed = check.get("Allowed") is True
            modified = check.get("Modified") is True
            modified_payload = check.get("ModifiedPayload") or ""
            behaviour = (check.get("behaviour") or "").lower()
            reason = check.get("Reason") or "Blocked by Akto request guardrails"

            if not allowed or behaviour == "block":
                flow.response = block_response(
                    reason=reason,
                    metadata=check.get("Metadata", {}),
                )
                return

            if modified and modified_payload:
                apply_masked_request(flow, modified_payload)

        except Exception as e:
            print(f"[AKTO] request guardrails call failed, allowing request: {e}")
            return

    def responseheaders(self, flow: http.HTTPFlow):
        if STREAM_GUARDRAILS and is_ai_provider(flow) and is_checkable_stream(flow):
            flow.response.stream = StreamGuard(flow)
            flow.metadata["akto_stream_checked"] = True

    def response(self, flow: http.HTTPFlow):
        if not is_ai_provider(flow):
            return

        # A streamed answer was already checked piece by piece and is ingested by its StreamGuard.
        if flow.metadata.get("akto_stream_checked"):
            return

        if flow.response.headers.get("X-Akto-Guardrails-Decision") == "blocked":
            return

        try:
            blocked, masked, reason, metadata = response_verdict(get_response_result(call_akto_response(flow)))
            if blocked:
                flow.response = block_response(reason=reason, metadata=metadata)
                return

            if masked:
                flow.response.set_text(masked)

        except Exception as e:
            print(f"[AKTO] response guardrails call failed, allowing response: {e}")
            return


addons = [AktoGuardrailsAddon()]
