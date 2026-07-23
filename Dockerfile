FROM python:3.13-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

COPY requirements-production.txt .

RUN python -m venv /opt/venv \
    && /opt/venv/bin/python -m pip install --upgrade pip \
    && /opt/venv/bin/python -m pip install \
        --no-cache-dir \
        -r requirements-production.txt

FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}" \
    PYTHONPATH=/app \
    SOC_CASE_DATABASE=/app/data/cases/soc_cases.db \
    SOC_INPUT_ROOT=/app/data/test_events \
    SOC_DEPLOYMENT_MODE=production \
    SOC_SESSION_HTTPS_ONLY=true \
    SOC_ENABLE_HSTS=true \
    SOC_LOG_FORMAT=json \
    SOC_LOG_LEVEL=INFO

RUN groupadd --system --gid 10001 soc \
    && useradd \
        --system \
        --uid 10001 \
        --gid soc \
        --home-dir /app \
        --shell /usr/sbin/nologin \
        soc

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY --chown=soc:soc . .

RUN mkdir -p \
        /app/data/cases \
        /app/data/test_events \
        /app/reports \
    && chown -R soc:soc \
        /app/data \
        /app/reports

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; response = urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=3); raise SystemExit(0 if response.status == 200 else 1)"

CMD ["python", "-m", "uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
