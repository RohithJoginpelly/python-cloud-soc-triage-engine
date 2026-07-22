"""Production-safe unhandled exception response tests."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from fastapi.testclient import TestClient

from src.api.app import create_app


PROJECT_ROOT = Path(
    __file__
).resolve().parents[2]

INPUT_ROOT = (
    PROJECT_ROOT
    / "data"
    / "test_events"
)

API_KEY = "safe-error-api-key"

SENSITIVE_ERROR = (
    "Runtime failure: "
    "password=Sensitive-Password-2026! "
    "api_key=private-api-key "
    "database=/tmp/private/soc_cases.db"
)


def build_app(tmp_path):
    """Create an application with failing test routes."""

    app = create_app(
        database_path=tmp_path / "cases.db",
        input_root=INPUT_ROOT,
        api_key=API_KEY,
        session_secret=(
            "safe-error-session-secret"
        ),
    )

    @app.get("/unexpected-api-error")
    def unexpected_api_error():
        raise RuntimeError(
            SENSITIVE_ERROR
        )

    @app.get("/dashboard/unexpected-error")
    def unexpected_dashboard_error():
        raise RuntimeError(
            SENSITIVE_ERROR
        )

    return app


def api_client(app) -> TestClient:
    """Create a client that inspects server errors."""

    return TestClient(
        app,
        raise_server_exceptions=False,
    )


def test_api_error_returns_safe_json(
    tmp_path,
):
    app = build_app(tmp_path)
    client = api_client(app)

    response = client.get(
        "/unexpected-api-error",
        headers={
            "X-SOC-API-Key": API_KEY,
        },
    )

    assert response.status_code == 500

    payload = response.json()

    assert payload["detail"] == (
        "An unexpected server error occurred."
    )

    reference = payload[
        "error_reference"
    ]

    assert re.fullmatch(
        r"[0-9a-f]{24}",
        reference,
    )

    assert response.headers[
        "x-error-reference"
    ] == reference

    assert response.headers[
        "cache-control"
    ] == "no-store"

    assert response.headers[
        "x-content-type-options"
    ] == "nosniff"

    assert SENSITIVE_ERROR not in response.text
    assert "Sensitive-Password-2026!" not in (
        response.text
    )
    assert "private-api-key" not in response.text
    assert "/tmp/private" not in response.text
    assert "RuntimeError" not in response.text
    assert "Traceback" not in response.text


def test_dashboard_error_returns_safe_html(
    tmp_path,
):
    app = build_app(tmp_path)
    client = api_client(app)

    response = client.get(
        "/dashboard/unexpected-error"
    )

    assert response.status_code == 500

    reference = response.headers[
        "x-error-reference"
    ]

    assert re.fullmatch(
        r"[0-9a-f]{24}",
        reference,
    )

    assert "Unexpected error" in response.text
    assert "The request could not be completed" in (
        response.text
    )
    assert reference in response.text

    assert response.headers[
        "content-type"
    ].startswith("text/html")

    assert response.headers[
        "cache-control"
    ] == "no-store"

    assert SENSITIVE_ERROR not in response.text
    assert "Sensitive-Password-2026!" not in (
        response.text
    )
    assert "private-api-key" not in response.text
    assert "/tmp/private" not in response.text
    assert "RuntimeError" not in response.text
    assert "Traceback" not in response.text


def test_error_references_are_unique(
    tmp_path,
):
    app = build_app(tmp_path)
    client = api_client(app)

    headers = {
        "X-SOC-API-Key": API_KEY,
    }

    first = client.get(
        "/unexpected-api-error",
        headers=headers,
    )

    second = client.get(
        "/unexpected-api-error",
        headers=headers,
    )

    assert first.status_code == 500
    assert second.status_code == 500

    assert first.headers[
        "x-error-reference"
    ] != second.headers[
        "x-error-reference"
    ]


def test_error_is_logged_with_reference(
    tmp_path,
    caplog,
):
    app = build_app(tmp_path)
    client = api_client(app)

    with caplog.at_level(
        logging.ERROR,
        logger="src.api.error_handling",
    ):
        response = client.get(
            "/unexpected-api-error",
            headers={
                "X-SOC-API-Key": API_KEY,
            },
        )

    assert response.status_code == 500

    reference = response.headers[
        "x-error-reference"
    ]

    matching_records = [
        record
        for record in caplog.records
        if reference in record.getMessage()
    ]

    assert len(matching_records) == 1

    record = matching_records[0]

    assert "GET" in record.getMessage()
    assert "/unexpected-api-error" in (
        record.getMessage()
    )


def test_normal_http_errors_are_not_converted(
    tmp_path,
):
    app = build_app(tmp_path)
    client = api_client(app)

    missing_key_response = client.get(
        "/unexpected-api-error"
    )

    assert missing_key_response.status_code == 401

    assert missing_key_response.json()[
        "detail"
    ] == "Invalid or missing SOC API key"

    assert (
        "x-error-reference"
        not in missing_key_response.headers
    )
