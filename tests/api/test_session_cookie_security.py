"""Session-cookie hardening and expiration tests."""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timedelta, timezone
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

TEST_EMAIL = "cookie.analyst@example.com"
TEST_PASSWORD = (
    "Secure-Cookie-Analyst-2026!"
)


def build_app(tmp_path):
    """Create an isolated application."""

    app = create_app(
        database_path=tmp_path / "cases.db",
        input_root=INPUT_ROOT,
        api_key="cookie-security-api-key",
        session_secret=(
            "cookie-security-session-secret"
        ),
    )

    account = (
        app.state.identity_store
        .create_account(
            email=TEST_EMAIL,
            display_name="Cookie Analyst",
            password=TEST_PASSWORD,
            role="analyst",
        )
    )

    return app, account


def extract_csrf(html: str) -> str:
    """Extract the rendered CSRF token."""

    match = re.search(
        r'name="csrf_token"\s+'
        r'value="([^"]+)"',
        html,
    )

    assert match is not None

    return match.group(1)


def login(client: TestClient) -> None:
    """Authenticate the test analyst."""

    page = client.get(
        "/dashboard/login"
    )

    assert page.status_code == 200

    response = client.post(
        "/dashboard/login",
        data={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD,
            "csrf_token": extract_csrf(
                page.text
            ),
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers[
        "location"
    ] == "/dashboard"


def active_session_id(
    app,
    *,
    user_id: str,
) -> str:
    """Return the user's newest active session."""

    database_path = (
        app.state.session_security_store
        .database_path
    )

    with sqlite3.connect(
        database_path
    ) as connection:
        row = connection.execute(
            """
            SELECT session_id
            FROM analyst_sessions
            WHERE
                user_id = ?
                AND revoked_at IS NULL
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (user_id,),
        ).fetchone()

    assert row is not None

    return str(row[0])


def test_cookie_has_required_security_attributes(
    tmp_path,
    monkeypatch,
):
    """Cookie uses HttpOnly, Lax, and eight-hour age."""

    monkeypatch.delenv(
        "SOC_SESSION_HTTPS_ONLY",
        raising=False,
    )

    app, _ = build_app(tmp_path)
    client = TestClient(app)

    response = client.get(
        "/dashboard/login"
    )

    assert response.status_code == 200

    set_cookie = response.headers[
        "set-cookie"
    ].lower()

    assert "httponly" in set_cookie
    assert "samesite=lax" in set_cookie
    assert "max-age=28800" in set_cookie

    # Local HTTP development does not require
    # the Secure cookie attribute.
    assert "secure" not in set_cookie


def test_secure_cookie_enabled_by_environment(
    tmp_path,
    monkeypatch,
):
    """Production HTTPS mode adds Secure."""

    monkeypatch.setenv(
        "SOC_SESSION_HTTPS_ONLY",
        "true",
    )

    app, _ = build_app(tmp_path)

    client = TestClient(
        app,
        base_url="https://testserver",
    )

    response = client.get(
        "/dashboard/login"
    )

    assert response.status_code == 200

    set_cookie = response.headers[
        "set-cookie"
    ].lower()

    assert "httponly" in set_cookie
    assert "samesite=lax" in set_cookie
    assert "max-age=28800" in set_cookie
    assert "secure" in set_cookie


def test_idle_expiration_redirects_to_notice(
    tmp_path,
    monkeypatch,
):
    """Idle sessions redirect to an expiration notice."""

    monkeypatch.delenv(
        "SOC_SESSION_HTTPS_ONLY",
        raising=False,
    )

    app, account = build_app(tmp_path)
    client = TestClient(app)

    login(client)

    session_id = active_session_id(
        app,
        user_id=account.user_id,
    )

    expired_last_seen = (
        datetime.now(timezone.utc)
        - timedelta(minutes=31)
    ).isoformat()

    database_path = (
        app.state.session_security_store
        .database_path
    )

    with sqlite3.connect(
        database_path
    ) as connection:
        connection.execute(
            """
            UPDATE analyst_sessions
            SET last_seen_at = ?
            WHERE session_id = ?
            """,
            (
                expired_last_seen,
                session_id,
            ),
        )

    response = client.get(
        "/dashboard",
        follow_redirects=False,
    )

    assert response.status_code == 303

    assert response.headers[
        "location"
    ] == (
        "/dashboard/login"
        "?notice=session-expired"
    )

    stored_session = (
        app.state.session_security_store
        .get_session(session_id)
    )

    assert stored_session is not None
    assert stored_session.is_revoked is True


def test_session_expiration_notice_is_visible(
    tmp_path,
    monkeypatch,
):
    """The login page explains why access ended."""

    monkeypatch.delenv(
        "SOC_SESSION_HTTPS_ONLY",
        raising=False,
    )

    app, _ = build_app(tmp_path)
    client = TestClient(app)

    response = client.get(
        "/dashboard/login"
        "?notice=session-expired"
    )

    assert response.status_code == 200

    assert (
        "Your session expired after a period"
        in response.text
    )

    assert (
        "of inactivity. Sign in again."
        in response.text
    )
