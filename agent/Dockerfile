FROM python:3.10-slim

WORKDIR /app

# Install system certs
RUN apt-get update && apt-get install -y ca-certificates && update-ca-certificates

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent.py .

# Environment defaults (can override at runtime)
ENV PYTHONUNBUFFERED=1

CMD ["python", "agent.py"]
