"""Operational liveness and readiness endpoint tests."""

from __future__ import annotations

import shutil
from pathlib import Path

from fastapi.testclient import TestClient

from src.api.app import create_app


API_KEY = "health-test-api-key"


def build_app(tmp_path: Path):
    """Create an isolated health-test application."""

    input_root = tmp_path / "telemetry"
    input_root.mkdir()

    app = create_app(
        database_path=(
            tmp_path / "cases.db"
        ),
        input_root=input_root,
        api_key=API_KEY,
        session_secret=(
            "health-test-session-secret"
        ),
    )

    return app, input_root


def test_legacy_health_endpoint_remains_compatible(
    tmp_path,
):
    app, _ = build_app(tmp_path)
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200

    assert response.json() == {
        "status": "healthy",
        "service": "ai-soc-copilot",
        "version": "2.0.0",
    }


def test_liveness_endpoint_is_public(
    tmp_path,
):
    app, _ = build_app(tmp_path)
    client = TestClient(app)

    response = client.get(
        "/health/live"
    )

    assert response.status_code == 200

    assert response.json() == {
        "status": "alive",
        "service": "ai-soc-copilot",
        "version": "2.0.0",
    }

    assert (
        "x-request-id"
        in response.headers
    )

    assert response.headers[
        "x-content-type-options"
    ] == "nosniff"


def test_readiness_reports_healthy_dependencies(
    tmp_path,
):
    app, _ = build_app(tmp_path)
    client = TestClient(app)

    response = client.get(
        "/health/ready"
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["status"] == "ready"

    assert payload["checks"][
        "database"
    ]["status"] == "healthy"

    assert payload["checks"][
        "input_root"
    ]["status"] == "healthy"


def test_missing_input_root_returns_503(
    tmp_path,
):
    app, input_root = build_app(
        tmp_path
    )
    client = TestClient(app)

    shutil.rmtree(input_root)

    response = client.get(
        "/health/ready"
    )

    assert response.status_code == 503

    payload = response.json()

    assert payload["status"] == (
        "not_ready"
    )

    assert payload["checks"][
        "input_root"
    ] == {
        "status": "unhealthy",
        "reason": (
            "input_root_unavailable"
        ),
    }


def test_database_failure_returns_safe_503(
    tmp_path,
):
    app, _ = build_app(tmp_path)

    # A directory cannot be opened as a SQLite
    # database file and produces a controlled failure.
    app.state.readiness_checker.database_path = (
        tmp_path
    )

    client = TestClient(app)

    response = client.get(
        "/health/ready"
    )

    assert response.status_code == 503

    payload = response.json()

    assert payload["status"] == (
        "not_ready"
    )

    assert payload["checks"][
        "database"
    ] == {
        "status": "unhealthy",
        "reason": "database_unavailable",
    }

    assert str(tmp_path) not in response.text
    assert "unable to open" not in (
        response.text.lower()
    )


def test_readiness_does_not_require_api_key(
    tmp_path,
):
    app, _ = build_app(tmp_path)
    client = TestClient(app)

    response = client.get(
        "/health/ready"
    )

    assert response.status_code == 200
    assert response.status_code != 401
