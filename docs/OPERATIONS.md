# AI SOC Copilot Operations Runbook

## Operational endpoints

### Liveness

`GET /health/live`

Confirms that the API process is running. It does not test persistent dependencies.

Expected healthy response:

```json
{
  "status": "alive",
  "service": "ai-soc-copilot",
  "version": "2.0.0"
}
```

### Readiness

`GET /health/ready`

Checks whether the SQLite case database and telemetry input directory are available.

- HTTP `200`: the service is ready.
- HTTP `503`: one or more required dependencies are unavailable.

Failure responses use generic component-level reasons and do not expose filesystem paths or internal exception details.

### Legacy health endpoint

`GET /health`

Retained for backward compatibility.

### Operational metrics

`GET /metrics`

This endpoint is protected and requires the `X-SOC-API-Key` header.

```bash
curl \
  -H "X-SOC-API-Key: $SOC_API_KEY" \
  http://127.0.0.1:8000/metrics
```

Metrics are process-local and reset whenever the application restarts. They contain low-cardinality operational counters and do not expose passwords, API keys, session identifiers, database paths, telemetry contents, or analyst evidence.

## Structured logging

Enable JSON application logs:

```bash
export SOC_LOG_FORMAT=json
export SOC_LOG_LEVEL=INFO
```

Supported levels are `DEBUG`, `INFO`, `WARNING`, `ERROR`, and `CRITICAL`.

Each HTTP response receives an `X-Request-ID`. A safe caller-provided request ID is preserved; otherwise, the application generates one.

## Health-probe examples

```bash
curl -i http://127.0.0.1:8000/health/live
curl -i http://127.0.0.1:8000/health/ready
```

A load balancer or container platform should use:

- `/health/live` to determine whether the process should be restarted.
- `/health/ready` to determine whether traffic should be routed to the process.

## Important limitation

The metrics store and rate limiter are in-memory and process-local. In a multi-worker deployment, each worker maintains separate counters and rate-limit state. A distributed deployment should use a shared backend such as Redis and a centralized monitoring platform.
