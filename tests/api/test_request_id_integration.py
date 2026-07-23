"""Application request-ID integration tests."""

from __future__ import annotations

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

API_KEY = "request-id-api-key"

GENERATED_ID_PATTERN = re.compile(
    r"^[0-9a-f]{32}$"
)


def build_app(tmp_path):
    """Create an isolated application."""

    app = create_app(
        database_path=tmp_path / "cases.db",
        input_root=INPUT_ROOT,
        api_key=API_KEY,
        session_secret=(
            "request-id-session-secret"
        ),
    )

    @app.get("/request-id-error")
    def request_id_error():
        raise RuntimeError(
            "Internal request-ID test failure"
        )

    return app


def test_normal_response_has_request_id(
    tmp_path,
):
    app = build_app(tmp_path)
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200

    request_id = response.headers[
        "x-request-id"
    ]

    assert GENERATED_ID_PATTERN.fullmatch(
        request_id
    )


def test_safe_incoming_request_id_is_preserved(
    tmp_path,
):
    app = build_app(tmp_path)
    client = TestClient(app)

    supplied_request_id = (
        "soc-case-ingestion-2026_07"
    )

    response = client.get(
        "/health",
        headers={
            "X-Request-ID": (
                supplied_request_id
            )
        },
    )

    assert response.status_code == 200

    assert response.headers[
        "x-request-id"
    ] == supplied_request_id


def test_api_authentication_error_has_request_id(
    tmp_path,
):
    app = build_app(tmp_path)
    client = TestClient(app)

    supplied_request_id = (
        "unauthorized-api-request-01"
    )

    response = client.get(
        "/cases",
        headers={
            "X-Request-ID": (
                supplied_request_id
            )
        },
    )

    assert response.status_code == 401

    assert response.headers[
        "x-request-id"
    ] == supplied_request_id


def test_safe_error_reuses_request_id(
    tmp_path,
):
    app = build_app(tmp_path)

    client = TestClient(
        app,
        raise_server_exceptions=False,
    )

    supplied_request_id = (
        "failed-api-request-2026"
    )

    response = client.get(
        "/request-id-error",
        headers={
            "X-SOC-API-Key": API_KEY,
            "X-Request-ID": (
                supplied_request_id
            ),
        },
    )

    assert response.status_code == 500

    assert response.headers[
        "x-request-id"
    ] == supplied_request_id

    assert response.json()[
        "request_id"
    ] == supplied_request_id

    assert response.headers[
        "x-error-reference"
    ] == response.json()[
        "error_reference"
    ]


def test_dashboard_error_reuses_request_id(
    tmp_path,
):
    app = build_app(tmp_path)

    @app.get("/dashboard/request-id-error")
    def dashboard_request_id_error():
        raise RuntimeError(
            "Dashboard internal failure"
        )

    client = TestClient(
        app,
        raise_server_exceptions=False,
    )

    supplied_request_id = (
        "dashboard-failure-2026"
    )

    response = client.get(
        "/dashboard/request-id-error",
        headers={
            "X-Request-ID": (
                supplied_request_id
            )
        },
    )

    assert response.status_code == 500

    assert response.headers[
        "x-request-id"
    ] == supplied_request_id

    assert supplied_request_id in (
        response.text
    )

    assert response.headers[
        "x-error-reference"
    ] in response.text
