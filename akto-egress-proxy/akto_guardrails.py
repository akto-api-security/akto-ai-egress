import json
import time
import zlib
import requests
from mitmproxy import http

import os

AKTO_URL = f"{os.getenv('AKTO_URL')}/api/http-proxy" if os.getenv("AKTO_URL") else None
AKTO_ENABLED = bool(AKTO_URL)
APP_NAME = os.getenv("APP_NAME")


AI_HOSTS = {
    "api.openai.com",
    "api.anthropic.com",
}

print(f"[AKTO] URL: {AKTO_URL}")

def is_ai_provider(flow: http.HTTPFlow) -> bool:
    return flow.request.pretty_host in AI_HOSTS


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
        "tag": json.dumps({"gen-ai": "Gen AI", "source": "AGENTIC"}),
        "metadata": json.dumps({"gen-ai": "Gen AI", "source": "AGENTIC"}),
        "contextSource": "AGENTIC",
    }
    return xx


def _call_akto(payload: dict, params: dict) -> dict:
    print(f"[AKTO →] sending to Akto API | params: {params} | payload: {payload}")
    r = requests.get(
        AKTO_URL,
        params=params,
        headers={"Content-Type": "application/json"},
        json=payload,
        timeout=15,
    )
    r.raise_for_status()
    result = r.json()
    print(f"[AKTO ←] response from Akto API | {result}")
    return result


def call_akto_request(flow: http.HTTPFlow) -> dict:
    print("[AKTO] request guardrail check")
    return _call_akto(
        build_akto_payload(flow),
        {"guardrails": "true", "ingest_data": "true"},
    )


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
                # Anthropic: text content
                delta = obj.get("delta", {})
                if delta.get("type") == "text_delta":
                    extracted_text += delta.get("text", "")
                # Anthropic: tool input (streamed JSON fragments)
                if delta.get("type") == "input_json_delta":
                    extracted_text += delta.get("partial_json", "")
                # Anthropic: tool name from content_block_start
                if obj.get("type") == "content_block_start":
                    block = obj.get("content_block", {})
                    if block.get("type") == "tool_use":
                        extracted_text += f"[tool:{block.get('name', '')}]"
                # OpenAI streaming format
                for choice in obj.get("choices", []):
                    extracted_text += choice.get("delta", {}).get("content", "") or ""
            except (json.JSONDecodeError, AttributeError):
                pass

    complete_bytes = b"\n\n".join(complete_parts)
    if complete_parts:
        complete_bytes += b"\n\n"

    return complete_bytes, leftover, extracted_text


def call_akto_response_stream(flow: http.HTTPFlow, text_chunk: str) -> dict:
    print(f"[AKTO] stream response guardrail check | {len(text_chunk)} chars | [{text_chunk}]")
    return _call_akto(
        build_akto_payload(flow, response_body=text_chunk, status_code=str(flow.response.status_code)),
        {"response_guardrails": "true", "ingest_data": "false"},
    )


def call_akto_response(flow: http.HTTPFlow) -> dict:
    print("[AKTO] full response guardrail check")
    return _call_akto(
        build_akto_payload(flow, response_body=flow.response.get_text(strict=False) or "", status_code=str(flow.response.status_code)),
        {"response_guardrails": "true", "ingest_data": "true"},
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


def block_response(reason: str, metadata=None, status_code: int = 403):
    return http.Response.make(
        status_code,
        json.dumps({
            "error": reason,
            "metadata": metadata or {},
        }),
        {"Content-Type": "application/json", "X-Akto-Guardrails-Decision": "blocked"},
    )


class AktoGuardrailsAddon:
    def responseheaders(self, flow: http.HTTPFlow):
        if not is_ai_provider(flow):
            return
        content_type = flow.response.headers.get("content-type", "")
        if "text/event-stream" not in content_type:
            return  # non-streaming response — let the response hook handle it
        content_encoding = flow.response.headers.get("content-encoding", "").lower()
        is_gzip = "gzip" in content_encoding
        flow.metadata["_akto_streaming"] = True
        flow.metadata["_akto_gzip"] = is_gzip
        if is_gzip:
            # Strip encoding so we can forward decoded bytes and inject plain-text SSE events on block
            del flow.response.headers["content-encoding"]
        flow.response.stream = self._make_stream_handler(flow)

    def _make_stream_handler(self, flow: http.HTTPFlow):
        # Single decoded buffer for forwarding — Content-Encoding was stripped in responseheaders
        # so we can inject plain-text SSE block events when needed.
        state = {
            "pending": b"",       # decoded bytes buffered for forwarding
            "decode_buffer": b"", # SSE parse window (decoded)
            "decompressor": (
                zlib.decompressobj(16 + zlib.MAX_WBITS)
                if flow.metadata.get("_akto_gzip")
                else None
            ),
        }

        def stream_handler(chunk: bytes):
            is_end = not chunk  # mitmproxy signals EOS with b""

            if is_end:
                to_send = state["pending"]
                state["pending"] = b""
                if to_send:
                    yield to_send
                return

            if state["decompressor"]:
                try:
                    decoded = state["decompressor"].decompress(chunk)
                except zlib.error as e:
                    print(f"[AKTO] decompression error (using raw): {e}")
                    decoded = chunk
            else:
                decoded = chunk

            state["pending"] += decoded
            state["decode_buffer"] += decoded
            _, leftover, chunk_text = extract_sse_events(state["decode_buffer"])
            state["decode_buffer"] = leftover

            if not chunk_text:
                print(f"[AKTO] stream chunk: empty text, skipping guardrail check")
                to_send = state["pending"]
                state["pending"] = b""
                yield to_send
                return

            try:
                result = call_akto_response_stream(flow, chunk_text)
                check = get_response_result(result)
                behaviour = (check.get("behaviour") or "").lower()
                if behaviour == "block":
                    reason = check.get("Reason") or "Blocked by Akto response guardrails"
                    print(f"[AKTO] stream blocked: {reason}")
                    # Discard buffered real content; deliver a terminal SSE error event
                    # so the client receives the block message and closes cleanly.
                    state["pending"] = b""
                    block_event = (
                        f'data: {json.dumps({"type": "error", "error": {"type": "permission_error", "message": reason}})}\n\n'
                        f'data: [DONE]\n\n'
                    ).encode()
                    yield block_event
                    return
                allowed = check.get("Allowed") is True
                if not allowed:
                    print(f"[AKTO] stream alert (allowed=false, behaviour={behaviour or 'none'}): {check.get('Reason', '')}")
            except Exception as e:
                print(f"[AKTO] stream guardrail error (fail open): {e}")

            to_send = state["pending"]
            state["pending"] = b""
            yield to_send

        return stream_handler

    def request(self, flow: http.HTTPFlow):
        if not is_ai_provider(flow):
            return

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
                flow.request.set_text(modified_payload)

        except Exception as e:
            return

    def response(self, flow: http.HTTPFlow):
        if not is_ai_provider(flow):
            return

        if flow.metadata.get("_akto_streaming"):
            return  # streaming path already ran guardrail checks

        if flow.response.headers.get("X-Akto-Guardrails-Decision") == "blocked":
            return

        try:
            result = call_akto_response(flow)
            check = get_response_result(result)

            behaviour = (check.get("behaviour") or "").lower()
            allowed = check.get("Allowed") is True
            modified = check.get("Modified") is True
            modified_payload = check.get("ModifiedPayload") or ""
            reason = check.get("Reason") or "Blocked by Akto response guardrails"

            if behaviour == "block":
                flow.response = block_response(
                    reason=reason,
                    metadata=check.get("Metadata", {}),
                )
                return

            if not allowed:
                print(f"[AKTO] response alert (allowed=false, behaviour={behaviour or 'none'}): {reason}")

            if modified and modified_payload:
                flow.response.set_text(modified_payload)

        except Exception as e:
            return


addons = [AktoGuardrailsAddon()]
