"""Safe runtime configuration endpoint tests."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi.testclient import TestClient

from src.api.app import create_app


API_KEY = (
    "Endpoint-API-Key-2026-"
    "A1b2C3d4E5f6G7h8"
)

SESSION_SECRET = (
    "Endpoint-Session-Secret-2026-"
    "A1b2C3d4E5f6G7h8I9j0K1l2M3n4"
)


def build_app(
    tmp_path: Path,
    monkeypatch,
):
    """Create an isolated configuration application."""

    monkeypatch.setenv(
        "SOC_DEPLOYMENT_MODE",
        "development",
    )
    monkeypatch.setenv(
        "SOC_LOG_FORMAT",
        "text",
    )
    monkeypatch.setenv(
        "SOC_LOG_LEVEL",
        "INFO",
    )

    input_root = tmp_path / "telemetry"
    input_root.mkdir()

    return create_app(
        database_path=tmp_path / "cases.db",
        input_root=input_root,
        api_key=API_KEY,
        session_secret=SESSION_SECRET,
    )


def test_configuration_endpoint_requires_api_key(
    tmp_path,
    monkeypatch,
):
    app = build_app(
        tmp_path,
        monkeypatch,
    )
    client = TestClient(app)

    response = client.get(
        "/configuration"
    )

    assert response.status_code == 401


def test_configuration_endpoint_returns_safe_report(
    tmp_path,
    monkeypatch,
):
    app = build_app(
        tmp_path,
        monkeypatch,
    )
    client = TestClient(app)

    response = client.get(
        "/configuration",
        headers={
            "X-SOC-API-Key": API_KEY,
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["status"] == "valid"
    assert payload["service"] == (
        "ai-soc-copilot"
    )
    assert payload["version"] == "2.0.0"

    configuration = payload[
        "configuration"
    ]

    assert configuration[
        "deployment_mode"
    ] == "development"

    assert configuration["valid"] is True
    assert "issues" in configuration

    assert API_KEY not in response.text
    assert (
        SESSION_SECRET
        not in response.text
    )
    assert str(tmp_path) not in (
        response.text
    )


def test_configuration_response_is_not_cached(
    tmp_path,
    monkeypatch,
):
    app = build_app(
        tmp_path,
        monkeypatch,
    )
    client = TestClient(app)

    response = client.get(
        "/configuration",
        headers={
            "X-SOC-API-Key": API_KEY,
            "X-Request-ID": (
                "configuration-request-2026"
            ),
        },
    )

    assert response.status_code == 200

    assert response.headers[
        "cache-control"
    ] == "no-store"

    assert response.headers[
        "x-request-id"
    ] == "configuration-request-2026"

    assert response.headers[
        "x-content-type-options"
    ] == "nosniff"


def test_configuration_openapi_documentation_exists(
    tmp_path,
    monkeypatch,
):
    app = build_app(
        tmp_path,
        monkeypatch,
    )
    client = TestClient(app)

    response = client.get(
        "/openapi.json"
    )

    assert response.status_code == 200

    operation = response.json()[
        "paths"
    ]["/configuration"]["get"]

    assert operation["summary"] == (
        "Get safe runtime configuration status"
    )

    assert "401" in operation["responses"]
    assert "429" in operation["responses"]


def test_startup_configuration_log_is_safe(
    tmp_path,
    monkeypatch,
    caplog,
):
    monkeypatch.setenv(
        "SOC_DEPLOYMENT_MODE",
        "development",
    )
    monkeypatch.setenv(
        "SOC_LOG_FORMAT",
        "text",
    )

    weak_api_key = (
        "weak-development-api-key"
    )
    weak_session_secret = (
        "weak-development-session-secret"
    )

    input_root = tmp_path / "telemetry"
    input_root.mkdir()

    with caplog.at_level(
        logging.WARNING,
        logger="soc.configuration",
    ):
        create_app(
            database_path=(
                tmp_path / "cases.db"
            ),
            input_root=input_root,
            api_key=weak_api_key,
            session_secret=(
                weak_session_secret
            ),
        )

    records = [
        record
        for record in caplog.records
        if getattr(
            record,
            "event_type",
            None,
        )
        == "runtime_configuration_validated"
    ]

    assert len(records) == 1

    record = records[0]

    assert record.valid is True
    assert record.deployment_mode == (
        "development"
    )
    assert record.warning_count >= 1
    assert record.error_count == 0

    serialized = str(
        record.__dict__
    )

    assert weak_api_key not in serialized
    assert (
        weak_session_secret
        not in serialized
    )
