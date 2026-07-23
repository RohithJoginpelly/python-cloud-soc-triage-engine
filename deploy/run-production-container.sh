#!/usr/bin/env bash
set -Eeuo pipefail

IMAGE="${SOC_IMAGE:-ai-soc-copilot:v2-production}"
CONTAINER="${SOC_CONTAINER_NAME:-ai-soc-copilot-v2}"
ENV_FILE="${SOC_ENV_FILE:-.env.production}"
DATA_DIR="${SOC_DATA_DIR:-$PWD/data/cases}"
INPUT_DIR="${SOC_INPUT_DIR:-$PWD/data/test_events}"
HOST_PORT="${SOC_PORT:-8000}"

if [[ ! -f "$ENV_FILE" ]]; then
    echo "Missing environment file: $ENV_FILE" >&2
    echo "Copy .env.production.example and configure independent secrets." >&2
    exit 1
fi

mkdir -p "$DATA_DIR" "$INPUT_DIR"

if docker info >/dev/null 2>&1; then
    DOCKER=(docker)
else
    DOCKER=(sudo docker)
fi

if "${DOCKER[@]}" container inspect "$CONTAINER" >/dev/null 2>&1; then
    echo "Container already exists: $CONTAINER" >&2
    echo "Stop it before starting another instance." >&2
    exit 1
fi

"${DOCKER[@]}" run \
    --detach \
    --rm \
    --name "$CONTAINER" \
    --publish "127.0.0.1:${HOST_PORT}:8000" \
    --env-file "$ENV_FILE" \
    --read-only \
    --tmpfs "/tmp:rw,noexec,nosuid,size=64m" \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --pids-limit 256 \
    --memory 768m \
    --cpus 1.0 \
    --mount "type=bind,src=${DATA_DIR},dst=/app/data/cases" \
    --mount "type=bind,src=${INPUT_DIR},dst=/app/data/test_events,readonly" \
    "$IMAGE"
