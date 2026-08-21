FROM python:3.11-slim@sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7 AS build

ENV PIP_NO_CACHE_DIR=1
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && python -m venv /opt/venv
COPY requirements.txt ./
RUN /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

FROM python:3.11-slim@sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SEMGREP_SEND_METRICS=off \
    HOME=/tmp/scanner-home \
    PATH=/opt/venv/bin:$PATH

WORKDIR /app
RUN useradd --no-create-home --uid 10001 --shell /usr/sbin/nologin scanner
COPY --from=build /opt/venv /opt/venv
COPY app ./app
COPY semgrep_rules ./semgrep_rules
COPY tests ./tests
RUN chown -R scanner:scanner /app
USER scanner
EXPOSE 8001
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001", "--no-access-log"]
