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

AI_HOSTS_PATTERN = "|".join(re.escape(h).replace(r"\*", r"[^:]*") for h in AI_HOSTS)
AI_HOSTS_RE = re.compile(rf"^(?:{AI_HOSTS_PATTERN})$", re.IGNORECASE)
# mitmproxy matches allow_hosts against "host:port", not the bare hostname.
ALLOW_HOSTS_REGEX = rf"^(?:{AI_HOSTS_PATTERN}):\d+$"

print(f"[AKTO] URL: {AKTO_URL}")
print(f"[AKTO] AI hosts: {AI_HOSTS}")

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
        "tag": json.dumps({"gen-ai": "Gen AI", "source": "AGENTIC"}),
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
            print(f"[AKTO] request guardrails call failed, allowing request: {e}")
            return

    def response(self, flow: http.HTTPFlow):
        if not is_ai_provider(flow):
            return


        if flow.response.headers.get("X-Akto-Guardrails-Decision") == "blocked":
            return

        try:
            result = call_akto_response(flow)
            check = get_response_result(result)

            allowed = check.get("Allowed") is True
            modified = check.get("Modified") is True
            modified_payload = check.get("ModifiedPayload") or ""
            behaviour = check.get("behaviour")
            reason = check.get("Reason") or "Blocked by Akto response guardrails"

            if not allowed or behaviour == "block":
                flow.response = block_response(
                    reason=reason,
                    metadata=check.get("Metadata", {}),
                )
                return

            if modified and modified_payload:
                flow.response.set_text(modified_payload)

        except Exception as e:
            print(f"[AKTO] response guardrails call failed, allowing response: {e}")
            return


addons = [AktoGuardrailsAddon()]
