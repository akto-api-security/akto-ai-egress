# Akto AI Egress Proxy

A mitmproxy-based egress proxy that sits between your AI agents and LLM providers (Anthropic, OpenAI), applying Akto guardrails in real time on every request and streaming response chunk.

## Quick Start

```bash
export ANTHROPIC_API_KEY=sk-ant-....
export AKTO_URL=...
export APP_NAME=...
docker compose up --build
```

## How It Works

Every outbound request from an agent to an AI provider flows through the proxy:

1. **Request check** — the prompt is sent to Akto guardrails before reaching the LLM. Blocked requests receive a graceful SSE response containing the block reason instead of a 403 error.
2. **Streaming response check** — LLM output is intercepted chunk by chunk. Chunks are accumulated until a text threshold is reached, then guardrailed as a batch. Approved batches are forwarded to the agent; blocked batches terminate the stream with a graceful block message.
3. **Full response check (non-streaming)** — for non-SSE responses, the complete response body is guardrailed before delivery.

### Streaming Architecture

- Each agent's stream is fully isolated — no shared mutable state between concurrent agents.
- A pipeline pattern fires the guardrail API call for batch N in the background while batch N+1 accumulates, minimising latency.
- `asyncio.wrap_future` is used to await batch results without blocking the mitmproxy event loop, enabling true concurrency across multiple simultaneous agents.
- Separate thread pools for hook-level checks and stream batch checks prevent streaming load from starving request guardrails.
- A shared `requests.Session` reuses TCP connections to the Akto API across all agents.

### Supported Providers

| Provider | Host | SSE format |
|---|---|---|
| Anthropic | `api.anthropic.com` | `event: / data:` with `content_block_delta` |
| OpenAI | `api.openai.com` | `data:` with `choices[0].delta.content` |

Tool calls are also guardrailed — the tool name and streamed input JSON are extracted and evaluated alongside text responses.

### Graceful Blocks

When a block is detected, the proxy returns a valid LLM streaming response (not a 403) so the agent handles it gracefully:

- **First batch blocked**: full SSE message sequence with the block reason as text content.
- **Mid-stream block**: continuation SSE events appending the block reason to the already-started stream, followed by a clean close.

## Environment Variables

### Proxy

| Variable | Required | Default | Description |
|---|---|---|---|
| `AKTO_URL` | Yes | — | Base URL of your Akto instance (e.g. `https://akto.example.com`) |
| `APP_NAME` | Yes | — | Sent as the `host` header to Akto to identify traffic per app |
| `AKTO_TEXT_THRESHOLD` | No | `600` | Chars of extracted text to accumulate before a guardrail batch check. Lower = faster detection, more API calls. Higher = fewer calls, more content delivered before a potential block. |
| `AKTO_LOG_PAYLOADS` | No | `false` | Set to `true` to log full request/response payloads to stdout. Latency is always logged regardless. |

### Example Agent (agent.py)

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | Yes | Anthropic API key for the test agent |

## Concurrent Agent Support

The proxy supports up to **8 concurrent streaming agents** out of the box. Request and response hook checks run on a separate pool of 4 workers so streaming load does not interfere with prompt-level checks.

## Proxy Features

- **Chunk-by-chunk streaming guardrail** — LLM output is held from the agent, guardrailed in batches, and only forwarded once approved. Nothing reaches the agent before it is validated.
- **Pipelined async checks** — while batch N is being evaluated by Akto, batch N+1 is already accumulating. The event loop is never blocked; all agents stream concurrently.
- **Tool call interception** — tool names and tool input (streamed as JSON fragments) are extracted and guardrailed alongside text, catching malicious tool invocations and indirect prompt injection via fetched content.
- **Graceful block responses** — blocked requests and responses are returned as valid LLM streaming messages containing the block reason, not HTTP errors. The agent handles them as normal responses.
- **Multi-provider support** — works transparently with both Anthropic and OpenAI streaming APIs, auto-detecting the provider per request.
- **Transparent gzip decompression** — compressed SSE responses are decompressed for guardrail evaluation and forwarded in their original compressed form to the agent.
- **Fail open** — if the Akto API is unreachable or times out, traffic is allowed through so agent availability is never blocked by guardrail infrastructure issues.
