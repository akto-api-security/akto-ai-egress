Run the following - 

```
export ANTHROPIC_API_KEY=sk-ant-....
export AKTO_URL=...
export APP_NAME=...        # identifies your app in Akto guardrails (sent as the host header)
docker compose up --build
```

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | Yes | Anthropic API key for the agent |
| `AKTO_URL` | Yes | Base URL of your Akto instance (e.g. `https://akto.example.com`). |
| `APP_NAME` | Yes | Name of your application. When set, it is sent as the `host` header in requests to Akto so you can identify traffic per app. |
| `AI_HOSTS` | No | Comma-separated hosts to intercept and run guardrails on; `*` matches any run of characters. Defaults to `api.openai.com,api.anthropic.com,chatgpt.com,bedrock-runtime.*.amazonaws.com,bedrock-agent-runtime.*.amazonaws.com`. All other traffic is tunnelled without inspection. |

To add a provider, add it to `AI_HOSTS` and to the `--ignore-hosts` regex in `docker-compose.yml`. A host is intercepted only if it is in both.
