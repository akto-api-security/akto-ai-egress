FROM mitmproxy/mitmproxy:latest

RUN python -m pip install --no-cache-dir requests

COPY akto_guardrails.py /addons/akto_guardrails.py

CMD ["mitmdump", "--listen-host", "0.0.0.0", "--listen-port", "8087", "-s", "/addons/akto_guardrails.py"]
