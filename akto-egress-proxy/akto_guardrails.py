import json
import os
import time
import zlib

import requests
from mitmproxy import http

AKTO_URL = f"{os.getenv('AKTO_URL')}/api/http-proxy" if os.getenv("AKTO_URL") else None
AKTO_ENABLED = bool(AKTO_URL)
APP_NAME = os.getenv("APP_NAME")

TEXT_THRESHOLD = 500  # chars of extracted text per guardrail batch

AI_HOSTS = {
    "api.openai.com",
    "api.anthropic.com",
}

_AGENTIC_TAG = json.dumps({"gen-ai": "Gen AI", "source": "AGENTIC"})
_REQUEST_PARAMS = {"guardrails": "true", "ingest_data": "true"}
_RESPONSE_PARAMS = {"response_guardrails": "true", "ingest_data": "true"}

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
    return _call_akto(build_akto_payload(flow), _REQUEST_PARAMS)


def call_akto_response_stream(flow: http.HTTPFlow, text_chunk: str) -> dict:
    print(f"[AKTO] stream response guardrail check | {len(text_chunk)} chars | [{text_chunk}]")
    return _call_akto(
        build_akto_payload(flow, response_body=text_chunk, status_code=str(flow.response.status_code)),
        _RESPONSE_PARAMS,
    )


def call_akto_response(flow: http.HTTPFlow) -> dict:
    print("[AKTO] full response guardrail check")
    return _call_akto(
        build_akto_payload(flow, response_body=flow.response.get_text(strict=False) or "", status_code=str(flow.response.status_code)),
        _RESPONSE_PARAMS,
    )


def _get_guardrails_result(result: dict) -> dict:
    return result.get("data", {}).get("guardrailsResult", {})


def get_request_result(result: dict) -> dict:
    gr = _get_guardrails_result(result)
    # handles both schema variants: requestResult nested or flat
    return gr.get("requestResult", gr)


def get_response_result(result: dict) -> dict:
    return _get_guardrails_result(result)


def block_response(reason: str, metadata=None, status_code: int = 403):
    return http.Response.make(
        status_code,
        json.dumps({
            "error": reason,
            "metadata": metadata or {},
        }),
        {"Content-Type": "application/json", "X-Akto-Guardrails-Decision": "blocked"},
    )


def _apply_guardrail_check(flow: http.HTTPFlow, check: dict, context: str, target) -> bool:
    """Apply guardrail result to flow. Returns True if the request/response was blocked."""
    behaviour = (check.get("behaviour") or "").lower()
    reason = check.get("Reason") or f"Blocked by Akto {context} guardrails"

    if behaviour == "block":
        flow.response = block_response(reason=reason, metadata=check.get("Metadata", {}))
        return True

    if check.get("Allowed") is not True:
        print(f"[AKTO] {context} alert (allowed=false, behaviour={behaviour or 'none'}): {reason}")

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
            "pending": b"",
            "decode_buffer": b"",
            "text_buffer": "",
            "decompressor": (
                zlib.decompressobj(16 + zlib.MAX_WBITS)
                if flow.metadata.get("_akto_gzip")
                else None
            ),
        }

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

                state["pending"] += decoded
                state["decode_buffer"] += decoded
                _, leftover, chunk_text = extract_sse_events(state["decode_buffer"])
                state["decode_buffer"] = leftover
                state["text_buffer"] += chunk_text

            should_flush = (
                len(state["text_buffer"]) >= TEXT_THRESHOLD
                or (is_end and state["pending"])
            )

            if not should_flush:
                return

            if not state["text_buffer"]:
                print("[AKTO] stream flush: empty text buffer, skipping guardrail check")
            else:
                try:
                    result = call_akto_response_stream(flow, state["text_buffer"])
                    check = get_response_result(result)
                    behaviour = (check.get("behaviour") or "").lower()
                    if behaviour == "block":
                        reason = check.get("Reason") or "Blocked by Akto response guardrails"
                        print(f"[AKTO] stream blocked: {reason}")
                        state["pending"] = b""
                        state["text_buffer"] = ""
                        block_event = (
                            f'data: {json.dumps({"type": "error", "error": {"type": "permission_error", "message": reason}})}\n\n'
                            f'data: [DONE]\n\n'
                        ).encode()
                        yield block_event
                        return
                    if check.get("Allowed") is not True:
                        print(f"[AKTO] stream alert (allowed=false, behaviour={behaviour or 'none'}): {check.get('Reason', '')}")
                except Exception as e:
                    print(f"[AKTO] stream guardrail error (fail open): {e}")

            to_send = state["pending"]
            state["pending"] = b""
            state["text_buffer"] = ""
            yield to_send

        return stream_handler

    def request(self, flow: http.HTTPFlow):
        if not is_ai_provider(flow):
            return
        try:
            check = get_request_result(call_akto_request(flow))
            _apply_guardrail_check(flow, check, "request", flow.request)
        except Exception as e:
            print(f"[AKTO] request guardrail error (fail open): {e}")

    def response(self, flow: http.HTTPFlow):
        if not is_ai_provider(flow):
            return
        if flow.metadata.get("_akto_streaming"):
            return
        if flow.response.headers.get("X-Akto-Guardrails-Decision") == "blocked":
            return
        try:
            check = get_response_result(call_akto_response(flow))
            _apply_guardrail_check(flow, check, "response", flow.response)
        except Exception as e:
            print(f"[AKTO] response guardrail error (fail open): {e}")


addons = [AktoGuardrailsAddon()]
