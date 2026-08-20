FROM python:3.11-slim

WORKDIR /app

# Install OS deps for Semgrep
RUN apt-get update && apt-get install -y --no-install-recommends \
    git build-essential && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY semgrep_rules ./semgrep_rules

EXPOSE 8001

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
