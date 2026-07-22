"""Server-side dashboard session integration tests."""

from __future__ import annotations

import re
import sqlite3
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

TEST_EMAIL = "session.analyst@example.com"
TEST_PASSWORD = (
    "Secure-Session-Password-2026!"
)


def build_app(tmp_path):
    """Create an isolated application and analyst."""

    app = create_app(
        database_path=tmp_path / "cases.db",
        input_root=INPUT_ROOT,
        api_key="server-session-api-key",
        session_secret=(
            "server-session-test-secret"
        ),
    )

    account = (
        app.state.identity_store
        .create_account(
            email=TEST_EMAIL,
            display_name="Session Analyst",
            password=TEST_PASSWORD,
            role="analyst",
        )
    )

    return app, account


def extract_csrf(html: str) -> str:
    """Extract the CSRF token from HTML."""

    match = re.search(
        r'name="csrf_token"\s+'
        r'value="([^"]+)"',
        html,
    )

    assert match is not None

    return match.group(1)


def login(client: TestClient):
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

    return response


def read_sessions(app):
    """Read analyst sessions from SQLite."""

    database_path = (
        app.state.session_security_store
        .database_path
    )

    connection = sqlite3.connect(
        database_path
    )

    connection.row_factory = sqlite3.Row

    try:
        rows = connection.execute(
            """
            SELECT
                session_id,
                user_id,
                created_at,
                last_seen_at,
                absolute_expires_at,
                idle_timeout_seconds,
                revoked_at
            FROM analyst_sessions
            ORDER BY created_at ASC
            """
        ).fetchall()
    finally:
        connection.close()

    return rows


def test_login_creates_server_side_session(
    tmp_path,
):
    app, account = build_app(tmp_path)
    client = TestClient(app)

    login(client)

    sessions = read_sessions(app)

    assert len(sessions) == 1

    session = sessions[0]

    assert session["user_id"] == (
        account.user_id
    )

    assert session["session_id"]
    assert session["revoked_at"] is None

    assert (
        session["idle_timeout_seconds"]
        == 30 * 60
    )

    dashboard = client.get(
        "/dashboard",
        follow_redirects=False,
    )

    assert dashboard.status_code == 200


def test_logout_revokes_server_side_session(
    tmp_path,
):
    app, _ = build_app(tmp_path)
    client = TestClient(app)

    login(client)

    sessions = read_sessions(app)

    assert len(sessions) == 1

    session_id = sessions[0][
        "session_id"
    ]

    dashboard = client.get(
        "/dashboard"
    )

    assert dashboard.status_code == 200

    logout_response = client.post(
        "/dashboard/logout",
        data={
            "csrf_token": extract_csrf(
                dashboard.text
            ),
        },
        follow_redirects=False,
    )

    assert logout_response.status_code == 303

    assert logout_response.headers[
        "location"
    ] == "/dashboard/login"

    stored_session = (
        app.state.session_security_store
        .get_session(session_id)
    )

    assert stored_session is not None
    assert stored_session.is_revoked is True

    protected_response = client.get(
        "/dashboard",
        follow_redirects=False,
    )

    assert protected_response.status_code in {
        302,
        303,
        307,
    }

    assert protected_response.headers[
        "location"
    ] == "/dashboard/login"


def test_revoked_session_cannot_access_dashboard(
    tmp_path,
):
    app, _ = build_app(tmp_path)
    client = TestClient(app)

    login(client)

    sessions = read_sessions(app)

    assert len(sessions) == 1

    session_id = sessions[0][
        "session_id"
    ]

    revoked = (
        app.state.session_security_store
        .revoke_session(session_id)
    )

    assert revoked is True

    response = client.get(
        "/dashboard",
        follow_redirects=False,
    )

    assert response.status_code in {
        302,
        303,
        307,
    }

    assert response.headers[
        "location"
    ] == "/dashboard/login"

    stored_session = (
        app.state.session_security_store
        .get_session(session_id)
    )

    assert stored_session is not None
    assert stored_session.is_revoked is True
