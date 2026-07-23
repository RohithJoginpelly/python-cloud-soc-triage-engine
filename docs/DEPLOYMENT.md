# Production Container Deployment

## Architecture

The production container runs the V2 FastAPI application on port `8000` using one Uvicorn worker.

One worker is intentional because the current metrics and rate limiter use process-local memory.

## Build the image

```bash
sudo docker build -t ai-soc-copilot:v2-production .
```

The container:

- Runs as non-root UID and GID `10001`
- Uses a read-only root filesystem when started with the production launcher
- Drops all Linux capabilities
- Enables `no-new-privileges`
- Uses persistent storage for the SQLite database
- Mounts telemetry input as read-only
- Exposes the application only on localhost
- Includes a Docker liveness health check

## Configure production secrets

```bash
cp .env.production.example .env.production
chmod 600 .env.production
```

Generate two different random values:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

Store the first value as `SOC_API_KEY` and the second as `SOC_SESSION_SECRET`.

Never commit `.env.production`.

## Start the container

```bash
./deploy/run-production-container.sh
```

The launcher binds the application to:

```text
127.0.0.1:8000
```

A TLS reverse proxy should expose the service publicly.

## Verify health

```bash
curl -i http://127.0.0.1:8000/health/live
curl -i http://127.0.0.1:8000/health/ready
```

## Stop the container

```bash
sudo docker stop ai-soc-copilot-v2
```

## Persistent data

The launcher mounts:

- `data/cases` at `/app/data/cases`
- `data/test_events` at `/app/data/test_events` as read-only

Back up the SQLite database before upgrades or destructive maintenance.

## Reverse-proxy requirements

The reverse proxy should:

- Terminate HTTPS
- Redirect HTTP to HTTPS
- Preserve the host header
- Forward the original client address
- Apply request timeouts and body-size limits
- Restrict access to `/metrics` and `/configuration`

Only configure trusted proxy CIDRs through `SOC_TRUSTED_PROXY_CIDRS` when requests actually pass through those proxies.
