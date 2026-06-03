import asyncio
import base64
import json
import os
import struct
import time
import zlib

from concurrent.futures import ThreadPoolExecutor

import requests
from mitmproxy import http

AKTO_URL = f"{os.getenv('AKTO_URL')}/api/http-proxy" if os.getenv("AKTO_URL") else None
APP_NAME = os.getenv("APP_NAME")

TEXT_THRESHOLD  = int(os.getenv("AKTO_TEXT_THRESHOLD", "600"))
LOG_PAYLOADS    = os.getenv("AKTO_LOG_PAYLOADS", "").lower() == "true"
ASYNC_MODE      = os.getenv("AKTO_GUARDRAILS_MODE", "async").lower() != "sync"
_hook_executor   = ThreadPoolExecutor(max_workers=4)   # request/response hook API calls
_stream_executor = ThreadPoolExecutor(max_workers=8)   # stream batch API calls (1 per agent)
_session = requests.Session()                          # shared connection pool to Akto

AI_HOSTS = {
    "api.openai.com",
    "api.anthropic.com",
    "bedrock-runtime.amazonaws.com",
}

_AGENTIC_TAG = json.dumps({"gen-ai": "Gen AI", "source": "AGENTIC"})
_REQUEST_PARAMS = {"guardrails": "true", "ingest_data": "true"}
_RESPONSE_PARAMS = {"response_guardrails": "true", "ingest_data": "true"}

print(
    f"[AKTO] starting"
    f" | url={AKTO_URL}"
    f" | mode={'async' if ASYNC_MODE else 'sync'}"
    f" | threshold={TEXT_THRESHOLD} chars"
    f" | log_payloads={LOG_PAYLOADS}"
    f" | hook_workers={_hook_executor._max_workers}"
    f" | stream_workers={_stream_executor._max_workers}"
    f" | stream_timeout=5s"
)

def is_ai_provider(flow: http.HTTPFlow) -> bool:
    host = flow.request.pretty_host
    if host in AI_HOSTS:
        return True
    # Bedrock uses region-specific endpoints: bedrock-runtime.us-east-1.amazonaws.com
    if host.startswith("bedrock-runtime.") and host.endswith(".amazonaws.com"):
        return True
    return False

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
        print(f"[AKTO] request  | {label} | url={AKTO_URL} params={params} | body={json.dumps(payload)}")
    t0 = time.time()
    r = _session.get(
        AKTO_URL,
        params=params,
        headers={"Content-Type": "application/json"},
        json=payload,
        timeout=timeout,
    )
    latency_ms = (time.time() - t0) * 1000
    check_type = label.replace(" payload", "")
    if LOG_PAYLOADS:
        print(f"[AKTO] response | {check_type} | status={r.status_code} | latency={latency_ms:.0f}ms | body={r.text}")
    else:
        print(f"[AKTO] response | {check_type} | status={r.status_code} | latency={latency_ms:.0f}ms")
    r.raise_for_status()
    return r.json()

async def _call_akto(payload: dict, params: dict, label: str = "payload") -> dict:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_hook_executor, lambda: _call_akto_sync(payload, params, label))

async def call_akto_request(flow: http.HTTPFlow) -> dict:
    print(f"[AKTO] REQUEST  | agent={_agent_id(flow)} | {flow.request.method} {flow.request.pretty_host}{flow.request.path}")
    return await _call_akto(build_akto_payload(flow), _REQUEST_PARAMS, label="request payload")

def call_akto_response_stream(flow: http.HTTPFlow, text_chunk: str) -> dict:
    # sync — called from _stream_executor in the stream handler
    if LOG_PAYLOADS:
        print(f"[AKTO] GUARDRAIL | agent={_agent_id(flow)} | sending to Akto | {len(text_chunk)} chars | response=[{text_chunk}]")
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

def parse_event_stream_frames(buffer: bytes) -> tuple:
    """
    Parse AWS binary event stream frames from a buffer.
    Frame layout:
      [4B total_length][4B headers_length][4B prelude_CRC][headers][payload][4B message_CRC]
    Returns: (list of payload bytes, leftover incomplete buffer)
    """
    payloads = []
    offset = 0
    while offset < len(buffer):
        if offset + 12 > len(buffer):
            break
        total_length = struct.unpack_from(">I", buffer, offset)[0]
        headers_length = struct.unpack_from(">I", buffer, offset + 4)[0]
        if offset + total_length > len(buffer):
            break
        payload_offset = offset + 8 + 4 + headers_length
        payload_length = total_length - 8 - 4 - headers_length - 4
        if payload_length > 0:
            payloads.append(buffer[payload_offset: payload_offset + payload_length])
        offset += total_length
    return payloads, buffer[offset:]

def extract_bedrock_text(payload: bytes) -> str:
    """
    Extract text content from a single Bedrock event stream frame payload.
    Handles: Claude via Bedrock, Converse API, Titan, Llama, Mistral, Cohere.
    """
    try:
        obj = json.loads(payload)

        # most Bedrock model-specific APIs wrap the delta in base64 "bytes"
        if "bytes" in obj:
            obj = json.loads(base64.b64decode(obj["bytes"]))

        # Claude via Bedrock invoke-with-response-stream (Anthropic delta format)
        delta = obj.get("delta", {})
        if delta.get("type") == "text_delta":
            return delta.get("text", "")
        if delta.get("type") == "input_json_delta":
            return delta.get("partial_json", "")

        # Bedrock Converse API — delta has {"text": "..."} directly, no "type" field
        if "text" in delta:
            return delta["text"]

        # Bedrock Converse API wrapper format
        content_block_delta = obj.get("contentBlockDelta", {})
        if content_block_delta:
            return content_block_delta.get("delta", {}).get("text", "") or ""

        # Amazon Titan
        if "outputText" in obj:
            return obj["outputText"]

        # Meta Llama
        if "generation" in obj:
            return obj["generation"]

        # Mistral
        outputs = obj.get("outputs", [])
        if outputs:
            return outputs[0].get("text", "")

        # Cohere
        if obj.get("event_type") == "text-generation":
            return obj.get("text", "")

    except Exception:
        pass
    return ""

class AktoGuardrailsAddon:
    def responseheaders(self, flow: http.HTTPFlow):
        if not is_ai_provider(flow):
            return
        content_type = flow.response.headers.get("content-type", "")

        if "application/vnd.amazon.eventstream" in content_type:
            flow.metadata["_akto_streaming"] = True
            if ASYNC_MODE:
                flow.response.stream = self._make_async_bedrock_stream_handler(flow)
            else:
                flow.response.stream = self._make_sync_bedrock_stream_handler(flow)
            return

        if "text/event-stream" not in content_type:
            return
        content_encoding = flow.response.headers.get("content-encoding", "").lower()
        is_gzip = "gzip" in content_encoding
        flow.metadata["_akto_streaming"] = True
        flow.metadata["_akto_gzip"] = is_gzip
        if is_gzip:
            del flow.response.headers["content-encoding"]
        if ASYNC_MODE:
            flow.response.stream = self._make_async_stream_handler(flow)
        else:
            flow.response.stream = self._make_stream_handler(flow)

    def _make_async_stream_handler(self, flow: http.HTTPFlow):
        """
        Zero-latency async tap (SSE): forward every chunk to the client immediately.
        Accumulates text in batches (TEXT_THRESHOLD chars), fires each batch to Akto
        as fire-and-forget. Client is never blocked regardless of guardrail result.
        """
        state = {
            "batch_text": "",
            "decode_buffer": b"",
            "decompressor": (
                zlib.decompressobj(16 + zlib.MAX_WBITS)
                if flow.metadata.get("_akto_gzip")
                else None
            ),
        }

        def _fire(text: str):
            print(f"[AKTO] STREAM   | agent={_agent_id(flow)} | firing async guardrail | {len(text)} chars")
            _stream_executor.submit(call_akto_response_stream, flow, text)

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

                state["decode_buffer"] += decoded
                _, leftover, chunk_text = extract_sse_events(state["decode_buffer"])
                state["decode_buffer"] = leftover
                state["batch_text"] += chunk_text

                if chunk_text and LOG_PAYLOADS:
                    print(f"[AKTO] STREAM   | agent={_agent_id(flow)} | chunk | [{chunk_text}]")

                yield decoded  # forward to client immediately, zero latency

                if len(state["batch_text"]) >= TEXT_THRESHOLD:
                    _fire(state["batch_text"])
                    state["batch_text"] = ""

            if is_end and state["batch_text"]:
                _fire(state["batch_text"])
                state["batch_text"] = ""

        return stream_handler

    def _make_async_bedrock_stream_handler(self, flow: http.HTTPFlow):
        """
        Zero-latency async tap for Bedrock binary event stream (application/vnd.amazon.eventstream).
        Forwards every frame to the client immediately, accumulates text in batches (TEXT_THRESHOLD),
        fires each batch to Akto as fire-and-forget. Client is never blocked.
        """
        state = {
            "batch_text": "",
            "frame_buffer": b"",
        }

        def _fire(text: str):
            print(f"[AKTO] STREAM   | agent={_agent_id(flow)} | firing async guardrail | {len(text)} chars")
            _stream_executor.submit(call_akto_response_stream, flow, text)

        def stream_handler(chunk: bytes):
            is_end = not chunk

            if not is_end:
                state["frame_buffer"] += chunk
                payloads, state["frame_buffer"] = parse_event_stream_frames(state["frame_buffer"])

                for payload in payloads:
                    text = extract_bedrock_text(payload)
                    if text:
                        state["batch_text"] += text
                        if LOG_PAYLOADS:
                            print(f"[AKTO] STREAM   | agent={_agent_id(flow)} | chunk | [{text}]")

                yield chunk  # forward to client immediately, zero latency

                if len(state["batch_text"]) >= TEXT_THRESHOLD:
                    _fire(state["batch_text"])
                    state["batch_text"] = ""

            if is_end and state["batch_text"]:
                _fire(state["batch_text"])
                state["batch_text"] = ""

        return stream_handler

    def _make_sync_bedrock_stream_handler(self, flow: http.HTTPFlow):
        """
        Sync pipeline handler for Bedrock binary event stream.
        Accumulates text in batches (TEXT_THRESHOLD), evaluates each batch through Akto.
        Can block the client mid-stream if a batch is rejected.
        """
        state = {
            "batch_bytes": b"",
            "batch_text": "",
            "frame_buffer": b"",
            "inflight": None,
        }

        def _wait_inflight():
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
                    reason = check.get("Reason") or "Blocked by Akto response guardrails"
                    print(f"[AKTO] STREAM   | agent={_agent_id(flow)} | decision=BLOCKED | {pipeline_ok} | {reason}")
                    return b"", reason
                if check.get("Allowed") is not True:
                    print(f"[AKTO] STREAM   | agent={_agent_id(flow)} | alert | {pipeline_ok} | {check.get('Reason', '')}")
                else:
                    print(f"[AKTO] STREAM   | agent={_agent_id(flow)} | allowed | {pipeline_ok}")
            except Exception as e:
                print(f"[AKTO] STREAM   | error (fail open) | {e}")
            return entry["bytes"], None

        def stream_handler(chunk: bytes):
            is_end = not chunk

            if not is_end:
                state["frame_buffer"] += chunk
                payloads, state["frame_buffer"] = parse_event_stream_frames(state["frame_buffer"])
                for payload in payloads:
                    text = extract_bedrock_text(payload)
                    if text:
                        state["batch_text"] += text
                        if LOG_PAYLOADS:
                            print(f"[AKTO] STREAM   | agent={_agent_id(flow)} | chunk | [{text}]")
                state["batch_bytes"] += chunk

            should_flush = (
                len(state["batch_text"]) >= TEXT_THRESHOLD
                or (is_end and (state["batch_bytes"] or state["inflight"]))
            )

            if not should_flush:
                return

            # Step 1: collect result from previous inflight batch
            if state["inflight"]:
                approved_bytes, block_reason = _wait_inflight()
                if block_reason:
                    state["batch_bytes"] = b""
                    state["batch_text"] = ""
                    return  # stop generator — mitmproxy closes connection
                yield approved_bytes

            # Step 2: fire current batch
            if state["batch_text"]:
                print(f"[AKTO] STREAM   | agent={_agent_id(flow)} | firing sync guardrail | {len(state['batch_text'])} chars")
                state["inflight"] = {
                    "future": _stream_executor.submit(call_akto_response_stream, flow, state["batch_text"]),
                    "bytes": state["batch_bytes"],
                }
                state["batch_bytes"] = b""
                state["batch_text"] = ""
            elif state["batch_bytes"]:
                yield state["batch_bytes"]
                state["batch_bytes"] = b""

            # Step 3: drain final inflight on stream end
            if is_end and state["inflight"]:
                approved_bytes, block_reason = _wait_inflight()
                if block_reason:
                    return  # stop generator — mitmproxy closes connection
                yield approved_bytes

        return stream_handler

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
