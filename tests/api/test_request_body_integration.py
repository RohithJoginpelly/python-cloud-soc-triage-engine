"""Application request-body limit integration tests."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi import Request
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

TEST_EMAIL = "body.analyst@example.com"
TEST_PASSWORD = (
    "Secure-Body-Analyst-2026!"
)

API_KEY = "request-body-api-key"


def build_app(
    tmp_path,
    monkeypatch,
    *,
    max_body_bytes: int,
):
    """Create an app with a configured body limit."""

    monkeypatch.setenv(
        "SOC_MAX_REQUEST_BODY_BYTES",
        str(max_body_bytes),
    )

    app = create_app(
        database_path=tmp_path / "cases.db",
        input_root=INPUT_ROOT,
        api_key=API_KEY,
        session_secret=(
            "request-body-session-secret"
        ),
    )

    app.state.identity_store.create_account(
        email=TEST_EMAIL,
        display_name="Body Analyst",
        password=TEST_PASSWORD,
        role="analyst",
    )

    @app.post("/request-body-test")
    async def request_body_test(
        request: Request,
    ):
        body = await request.body()

        return {
            "size": len(body),
        }

    return app


def extract_csrf(html: str) -> str:
    """Extract a rendered CSRF token."""

    match = re.search(
        r'name="csrf_token"\s+'
        r'value="([^"]+)"',
        html,
    )

    assert match is not None

    return match.group(1)


def test_oversized_login_form_returns_413(
    tmp_path,
    monkeypatch,
):
    app = build_app(
        tmp_path,
        monkeypatch,
        max_body_bytes=64,
    )

    client = TestClient(app)

    login_page = client.get(
        "/dashboard/login"
    )

    assert login_page.status_code == 200

    response = client.post(
        "/dashboard/login",
        data={
            "email": TEST_EMAIL,
            "password": "X" * 200,
            "csrf_token": extract_csrf(
                login_page.text
            ),
        },
        follow_redirects=False,
    )

    assert response.status_code == 413

    assert response.json()["detail"] == (
        "Request body exceeds the "
        "configured size limit."
    )

    assert response.headers[
        "x-max-request-body-bytes"
    ] == "64"

    assert response.headers[
        "x-content-type-options"
    ] == "nosniff"


def test_oversized_protected_api_body_returns_413(
    tmp_path,
    monkeypatch,
):
    app = build_app(
        tmp_path,
        monkeypatch,
        max_body_bytes=32,
    )

    client = TestClient(app)

    response = client.post(
        "/request-body-test",
        headers={
            "X-SOC-API-Key": API_KEY,
        },
        content=b"A" * 33,
    )

    assert response.status_code == 413

    assert response.headers[
        "x-max-request-body-bytes"
    ] == "32"

    assert response.json()["detail"] == (
        "Request body exceeds the "
        "configured size limit."
    )


def test_body_within_limit_reaches_api_route(
    tmp_path,
    monkeypatch,
):
    app = build_app(
        tmp_path,
        monkeypatch,
        max_body_bytes=32,
    )

    client = TestClient(app)

    response = client.post(
        "/request-body-test",
        headers={
            "X-SOC-API-Key": API_KEY,
        },
        content=b"A" * 32,
    )

    assert response.status_code == 200

    assert response.json() == {
        "size": 32,
    }


def test_invalid_body_limit_environment_fails(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv(
        "SOC_MAX_REQUEST_BODY_BYTES",
        "not-an-integer",
    )

    with pytest.raises(
        ValueError,
        match=(
            "SOC_MAX_REQUEST_BODY_BYTES "
            "must be an integer"
        ),
    ):
        create_app(
            database_path=tmp_path / "cases.db",
            input_root=INPUT_ROOT,
            api_key=API_KEY,
            session_secret=(
                "invalid-body-limit-secret"
            ),
        )


def test_non_positive_body_limit_fails(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv(
        "SOC_MAX_REQUEST_BODY_BYTES",
        "0",
    )

    with pytest.raises(
        ValueError,
        match=(
            "SOC_MAX_REQUEST_BODY_BYTES "
            "must be positive"
        ),
    ):
        create_app(
            database_path=tmp_path / "cases.db",
            input_root=INPUT_ROOT,
            api_key=API_KEY,
            session_secret=(
                "invalid-body-limit-secret"
            ),
        )
