"""Operational metrics and integration tests."""

from __future__ import annotations

from pathlib import Path

from fastapi import Request
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.api.metrics import OperationalMetrics


API_KEY = "operational-metrics-api-key"


def build_app(
    tmp_path: Path,
    monkeypatch,
    *,
    api_limit: int = 100,
    body_limit: int = 1024,
):
    """Create an isolated metrics application."""

    monkeypatch.setenv(
        "SOC_API_RATE_LIMIT",
        str(api_limit),
    )
    monkeypatch.setenv(
        "SOC_API_RATE_WINDOW_SECONDS",
        "60",
    )
    monkeypatch.setenv(
        "SOC_MAX_REQUEST_BODY_BYTES",
        str(body_limit),
    )

    input_root = tmp_path / "telemetry"
    input_root.mkdir()

    app = create_app(
        database_path=tmp_path / "cases.db",
        input_root=input_root,
        api_key=API_KEY,
        session_secret=(
            "operational-metrics-secret"
        ),
    )

    @app.get("/metrics-test-ok")
    def metrics_test_ok():
        return {"status": "ok"}

    @app.post("/metrics-test-body")
    async def metrics_test_body(
        request: Request,
    ):
        body = await request.body()

        return {
            "size": len(body),
        }

    return app


def test_snapshot_calculates_http_and_security_totals():
    metrics = OperationalMetrics()

    metrics.record_http_request(
        status_code=200,
        duration_ms=10,
    )
    metrics.record_http_request(
        status_code=401,
        duration_ms=20,
    )
    metrics.record_http_request(
        status_code=500,
        duration_ms=30,
    )

    metrics.record_security_event(
        "login_failed"
    )
    metrics.record_security_event(
        "account_locked"
    )
    metrics.record_security_event(
        "api_rate_limited"
    )
    metrics.record_security_event(
        "request_body_rejected"
    )

    snapshot = metrics.snapshot()

    assert snapshot["http"][
        "requests_total"
    ] == 3

    assert snapshot["http"][
        "responses_by_class"
    ]["2xx"] == 1

    assert snapshot["http"][
        "responses_by_class"
    ]["4xx"] == 1

    assert snapshot["http"][
        "responses_by_class"
    ]["5xx"] == 1

    assert snapshot["http"][
        "duration_ms"
    ]["average"] == 20.0

    assert snapshot["security"][
        "authentication_denials_total"
    ] == 1

    assert snapshot["security"][
        "account_lockouts_total"
    ] == 1

    assert snapshot["security"][
        "rate_limited_requests_total"
    ] == 1

    assert snapshot["security"][
        "request_body_rejections_total"
    ] == 1


def test_metrics_endpoint_requires_api_key(
    tmp_path,
    monkeypatch,
):
    app = build_app(
        tmp_path,
        monkeypatch,
    )
    client = TestClient(app)

    response = client.get("/metrics")

    assert response.status_code == 401


def test_metrics_endpoint_returns_safe_snapshot(
    tmp_path,
    monkeypatch,
):
    app = build_app(
        tmp_path,
        monkeypatch,
    )

    app.state.operational_metrics.record_http_request(
        status_code=200,
        duration_ms=12.5,
    )

    app.state.operational_metrics.record_security_event(
        "login_failed"
    )

    client = TestClient(app)

    response = client.get(
        "/metrics",
        headers={
            "X-SOC-API-Key": API_KEY,
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["status"] == "ok"
    assert payload["service"] == (
        "ai-soc-copilot"
    )
    assert payload["version"] == "2.0.0"

    assert payload["http"][
        "requests_total"
    ] == 1

    assert payload["security"][
        "events_by_type"
    ]["login_failed"] == 1

    assert response.headers[
        "cache-control"
    ] == "no-store"

    assert (
        "x-request-id"
        in response.headers
    )

    assert str(tmp_path) not in (
        response.text
    )


def test_http_middleware_records_responses(
    tmp_path,
    monkeypatch,
):
    app = build_app(
        tmp_path,
        monkeypatch,
    )
    client = TestClient(app)

    healthy = client.get("/health")
    unauthorized = client.get("/cases")

    assert healthy.status_code == 200
    assert unauthorized.status_code == 401

    snapshot = (
        app.state.operational_metrics.snapshot()
    )

    assert snapshot["http"][
        "requests_total"
    ] == 2

    assert snapshot["http"][
        "responses_by_class"
    ]["2xx"] == 1

    assert snapshot["http"][
        "responses_by_class"
    ]["4xx"] == 1


def test_security_events_update_metrics(
    tmp_path,
    monkeypatch,
):
    app = build_app(
        tmp_path,
        monkeypatch,
        body_limit=16,
    )
    client = TestClient(app)

    invalid_auth = client.get(
        "/cases",
        headers={
            "X-SOC-API-Key": (
                "invalid-metrics-key"
            )
        },
    )

    oversized = client.post(
        "/metrics-test-body",
        headers={
            "X-SOC-API-Key": API_KEY,
        },
        content=b"A" * 17,
    )

    assert invalid_auth.status_code == 401
    assert oversized.status_code == 413

    snapshot = (
        app.state.operational_metrics.snapshot()
    )

    assert snapshot["security"][
        "events_by_type"
    ]["api_authentication_failed"] == 1

    assert snapshot["security"][
        "events_by_type"
    ]["request_body_rejected"] == 1

    assert snapshot["security"][
        "authentication_denials_total"
    ] == 1

    assert snapshot["security"][
        "request_body_rejections_total"
    ] == 1


def test_api_rate_limit_updates_metrics(
    tmp_path,
    monkeypatch,
):
    app = build_app(
        tmp_path,
        monkeypatch,
        api_limit=1,
    )
    client = TestClient(app)

    headers = {
        "X-SOC-API-Key": API_KEY,
    }

    first = client.get(
        "/metrics-test-ok",
        headers=headers,
    )

    blocked = client.get(
        "/metrics-test-ok",
        headers=headers,
    )

    assert first.status_code == 200
    assert blocked.status_code == 429

    snapshot = (
        app.state.operational_metrics.snapshot()
    )

    assert snapshot["security"][
        "rate_limited_requests_total"
    ] == 1

    assert snapshot["security"][
        "events_by_type"
    ]["api_rate_limited"] == 1
