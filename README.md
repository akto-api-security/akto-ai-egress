Run the following - 

```
export ANTHROPIC_API_KEY=sk-ant-....
export AKTO_URL=...
export APP_NAME=...        # optional: identifies your app in Akto guardrails (sent as the host header)
docker compose up --build
```

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | Yes | Anthropic API key for the agent |
| `AKTO_URL` | Yes | Base URL of your Akto instance (e.g. `https://akto.example.com`). |
| `APP_NAME` | No | Name of your application. When set, it is sent as the `host` header in requests to Akto so you can identify traffic per app. |
