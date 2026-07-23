"""Integration tests for structured security events."""

from __future__ import annotations

import logging
import re
from pathlib import Path

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

EMAIL = "events.analyst@example.com"
PASSWORD = "Secure-Events-Analyst-2026!"
API_KEY = "security-events-api-key"


def build_app(
    tmp_path,
    monkeypatch,
    *,
    login_limit: int = 20,
    api_limit: int = 20,
    body_limit: int = 1024,
):
    monkeypatch.setenv(
        "SOC_LOGIN_RATE_LIMIT",
        str(login_limit),
    )
    monkeypatch.setenv(
        "SOC_LOGIN_RATE_WINDOW_SECONDS",
        "60",
    )
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

    app = create_app(
        database_path=tmp_path / "cases.db",
        input_root=INPUT_ROOT,
        api_key=API_KEY,
        session_secret="events-session-secret",
    )

    app.state.identity_store.create_account(
        email=EMAIL,
        display_name="Events Analyst",
        password=PASSWORD,
        role="analyst",
    )

    @app.get("/events-api")
    def events_api():
        return {"status": "ok"}

    @app.post("/events-body")
    async def events_body(
        request: Request,
    ):
        body = await request.body()
        return {"size": len(body)}

    return app


def extract_csrf(html: str) -> str:
    match = re.search(
        r'name="csrf_token"\s+'
        r'value="([^"]+)"',
        html,
    )
    assert match is not None
    return match.group(1)


def failed_login(client: TestClient):
    page = client.get("/dashboard/login")

    return client.post(
        "/dashboard/login",
        data={
            "email": EMAIL,
            "password": "Incorrect-Events-Password!",
            "csrf_token": extract_csrf(
                page.text
            ),
        },
        follow_redirects=False,
    )


def event_records(
    caplog,
    event_type: str,
):
    return [
        record
        for record in caplog.records
        if getattr(
            record,
            "event_type",
            None,
        )
        == event_type
    ]


def test_failed_login_is_logged(
    tmp_path,
    monkeypatch,
    caplog,
):
    app = build_app(
        tmp_path,
        monkeypatch,
    )
    client = TestClient(app)

    with caplog.at_level(
        logging.WARNING,
        logger="soc.security",
    ):
        response = failed_login(client)

    assert response.status_code == 401

    records = event_records(
        caplog,
        "login_failed",
    )

    assert len(records) == 1

    record = records[0]

    assert record.status_code == 401
    assert record.reason == (
        "invalid_credentials"
    )
    assert record.account_email == EMAIL
    assert record.request_id == (
        response.headers["x-request-id"]
    )


def test_account_lockout_is_logged(
    tmp_path,
    monkeypatch,
    caplog,
):
    app = build_app(
        tmp_path,
        monkeypatch,
    )
    client = TestClient(app)

    with caplog.at_level(
        logging.WARNING,
        logger="soc.security",
    ):
        for _ in range(5):
            response = failed_login(client)

    assert response.status_code == 401

    records = event_records(
        caplog,
        "account_locked",
    )

    assert len(records) == 1
    assert records[0].failed_attempts == 5


def test_login_rate_limit_is_logged(
    tmp_path,
    monkeypatch,
    caplog,
):
    app = build_app(
        tmp_path,
        monkeypatch,
        login_limit=1,
    )
    client = TestClient(app)

    failed_login(client)

    with caplog.at_level(
        logging.WARNING,
        logger="soc.security",
    ):
        blocked = failed_login(client)

    assert blocked.status_code == 429

    records = event_records(
        caplog,
        "login_rate_limited",
    )

    assert len(records) == 1
    assert records[0].status_code == 429


def test_invalid_api_key_is_logged_without_key(
    tmp_path,
    monkeypatch,
    caplog,
):
    app = build_app(
        tmp_path,
        monkeypatch,
    )
    client = TestClient(app)

    with caplog.at_level(
        logging.WARNING,
        logger="soc.security",
    ):
        response = client.get(
            "/events-api",
            headers={
                "X-SOC-API-Key": (
                    "attacker-supplied-key"
                )
            },
        )

    assert response.status_code == 401

    records = event_records(
        caplog,
        "api_authentication_failed",
    )

    assert len(records) == 1

    serialized = str(
        records[0].__dict__
    )

    assert (
        "attacker-supplied-key"
        not in serialized
    )


def test_api_rate_limit_is_logged(
    tmp_path,
    monkeypatch,
    caplog,
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
        "/events-api",
        headers=headers,
    )
    assert first.status_code == 200

    with caplog.at_level(
        logging.WARNING,
        logger="soc.security",
    ):
        blocked = client.get(
            "/events-api",
            headers=headers,
        )

    assert blocked.status_code == 429

    records = event_records(
        caplog,
        "api_rate_limited",
    )

    assert len(records) == 1
    assert records[0].status_code == 429


def test_oversized_body_is_logged(
    tmp_path,
    monkeypatch,
    caplog,
):
    app = build_app(
        tmp_path,
        monkeypatch,
        body_limit=16,
    )
    client = TestClient(app)

    with caplog.at_level(
        logging.WARNING,
        logger="soc.security",
    ):
        response = client.post(
            "/events-body",
            headers={
                "X-SOC-API-Key": API_KEY,
            },
            content=b"A" * 17,
        )

    assert response.status_code == 413

    records = event_records(
        caplog,
        "request_body_rejected",
    )

    assert len(records) == 1
    assert records[0].status_code == 413
    assert records[0].max_body_bytes == 16
