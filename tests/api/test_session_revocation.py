"""Session revocation after identity security changes."""

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

ADMIN_EMAIL = "session.admin@example.com"
ADMIN_PASSWORD = (
    "Secure-Session-Admin-2026!"
)

ANALYST_EMAIL = "session.analyst@example.com"
ANALYST_PASSWORD = (
    "Secure-Session-Analyst-2026!"
)

NEW_ANALYST_PASSWORD = (
    "New-Session-Analyst-2026!"
)

RESET_ANALYST_PASSWORD = (
    "Reset-Session-Analyst-2026!"
)


def build_app(tmp_path):
    """Create an isolated app with admin and analyst."""

    app = create_app(
        database_path=tmp_path / "cases.db",
        input_root=INPUT_ROOT,
        api_key="session-revocation-api-key",
        session_secret=(
            "session-revocation-test-secret"
        ),
    )

    admin = (
        app.state.identity_store
        .create_account(
            email=ADMIN_EMAIL,
            display_name="Session Admin",
            password=ADMIN_PASSWORD,
            role="admin",
        )
    )

    analyst = (
        app.state.identity_store
        .create_account(
            email=ANALYST_EMAIL,
            display_name="Session Analyst",
            password=ANALYST_PASSWORD,
            role="analyst",
        )
    )

    return app, admin, analyst


def extract_csrf(html: str) -> str:
    """Extract a CSRF token from rendered HTML."""

    match = re.search(
        r'name="csrf_token"\s+'
        r'value="([^"]+)"',
        html,
    )

    assert match is not None

    return match.group(1)


def login(
    client: TestClient,
    *,
    email: str,
    password: str,
) -> None:
    """Authenticate one dashboard client."""

    page = client.get(
        "/dashboard/login"
    )

    assert page.status_code == 200

    response = client.post(
        "/dashboard/login",
        data={
            "email": email,
            "password": password,
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
    """Return the newest active session for a user."""

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


def assert_session_revoked(
    app,
    *,
    session_id: str,
) -> None:
    """Assert that a server-side session was revoked."""

    session = (
        app.state.session_security_store
        .get_session(session_id)
    )

    assert session is not None
    assert session.is_revoked is True


def assert_dashboard_requires_login(
    client: TestClient,
) -> None:
    """Assert that the client lost dashboard access."""

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


def test_password_change_revokes_active_sessions(
    tmp_path,
):
    app, _, analyst = build_app(tmp_path)

    analyst_client = TestClient(app)

    login(
        analyst_client,
        email=ANALYST_EMAIL,
        password=ANALYST_PASSWORD,
    )

    session_id = active_session_id(
        app,
        user_id=analyst.user_id,
    )

    password_page = analyst_client.get(
        "/dashboard/account/password"
    )

    assert password_page.status_code == 200

    response = analyst_client.post(
        "/dashboard/account/password",
        data={
            "csrf_token": extract_csrf(
                password_page.text
            ),
            "current_password": (
                ANALYST_PASSWORD
            ),
            "new_password": (
                NEW_ANALYST_PASSWORD
            ),
            "new_password_confirmation": (
                NEW_ANALYST_PASSWORD
            ),
        },
        follow_redirects=False,
    )

    assert response.status_code == 303

    assert response.headers[
        "location"
    ] == (
        "/dashboard/login"
        "?notice=password-changed"
    )

    assert_session_revoked(
        app,
        session_id=session_id,
    )

    assert_dashboard_requires_login(
        analyst_client
    )


def test_admin_password_reset_revokes_sessions(
    tmp_path,
):
    app, _, analyst = build_app(tmp_path)

    analyst_client = TestClient(app)
    admin_client = TestClient(app)

    login(
        analyst_client,
        email=ANALYST_EMAIL,
        password=ANALYST_PASSWORD,
    )

    session_id = active_session_id(
        app,
        user_id=analyst.user_id,
    )

    login(
        admin_client,
        email=ADMIN_EMAIL,
        password=ADMIN_PASSWORD,
    )

    admin_page = admin_client.get(
        "/dashboard/admin/analysts"
    )

    assert admin_page.status_code == 200

    response = admin_client.post(
        (
            "/dashboard/admin/analysts/"
            f"{analyst.user_id}/password-reset"
        ),
        data={
            "csrf_token": extract_csrf(
                admin_page.text
            ),
            "new_password": (
                RESET_ANALYST_PASSWORD
            ),
            "new_password_confirmation": (
                RESET_ANALYST_PASSWORD
            ),
        },
        follow_redirects=False,
    )

    assert response.status_code == 303

    assert_session_revoked(
        app,
        session_id=session_id,
    )

    assert_dashboard_requires_login(
        analyst_client
    )


def test_disabling_account_revokes_sessions(
    tmp_path,
):
    app, _, analyst = build_app(tmp_path)

    analyst_client = TestClient(app)
    admin_client = TestClient(app)

    login(
        analyst_client,
        email=ANALYST_EMAIL,
        password=ANALYST_PASSWORD,
    )

    session_id = active_session_id(
        app,
        user_id=analyst.user_id,
    )

    login(
        admin_client,
        email=ADMIN_EMAIL,
        password=ADMIN_PASSWORD,
    )

    admin_page = admin_client.get(
        "/dashboard/admin/analysts"
    )

    assert admin_page.status_code == 200

    response = admin_client.post(
        (
            "/dashboard/admin/analysts/"
            f"{analyst.user_id}/active"
        ),
        data={
            "csrf_token": extract_csrf(
                admin_page.text
            ),
            "is_active": "false",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303

    disabled_account = (
        app.state.identity_store
        .get_by_id(analyst.user_id)
    )

    assert disabled_account is not None
    assert disabled_account.is_active is False

    assert_session_revoked(
        app,
        session_id=session_id,
    )

    assert_dashboard_requires_login(
        analyst_client
    )
