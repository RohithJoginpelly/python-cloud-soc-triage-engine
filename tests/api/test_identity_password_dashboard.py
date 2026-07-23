"""Password-management dashboard tests."""

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

ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = (
    "Secure-Admin-Password-2026!"
)

ANALYST_EMAIL = "analyst@example.com"
ANALYST_PASSWORD = (
    "Secure-Analyst-Password-2026!"
)

NEW_ANALYST_PASSWORD = (
    "Secure-New-Analyst-Password-2026!"
)

RESET_ANALYST_PASSWORD = (
    "Secure-Reset-Analyst-Password-2026!"
)


def build_app(tmp_path):
    app = create_app(
        database_path=tmp_path / "cases.db",
        input_root=INPUT_ROOT,
        api_key="identity-dashboard-api-key",
        session_secret=(
            "identity-dashboard-session-secret"
        ),
    )

    app.state.identity_store.create_account(
        email=ADMIN_EMAIL,
        display_name="Admin User",
        password=ADMIN_PASSWORD,
        role="admin",
    )

    app.state.identity_store.create_account(
        email=ANALYST_EMAIL,
        display_name="Analyst User",
        password=ANALYST_PASSWORD,
        role="analyst",
    )

    return app


def extract_csrf(html: str) -> str:
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


def test_analyst_can_view_password_page(
    tmp_path,
):
    app = build_app(tmp_path)
    client = TestClient(app)

    login(
        client,
        email=ANALYST_EMAIL,
        password=ANALYST_PASSWORD,
    )

    response = client.get(
        "/dashboard/account/password"
    )

    assert response.status_code == 200
    assert "Change password" in response.text
    assert ANALYST_EMAIL in response.text


def test_analyst_can_change_password(
    tmp_path,
):
    app = build_app(tmp_path)
    client = TestClient(app)

    login(
        client,
        email=ANALYST_EMAIL,
        password=ANALYST_PASSWORD,
    )

    page = client.get(
        "/dashboard/account/password"
    )

    response = client.post(
        "/dashboard/account/password",
        data={
            "csrf_token": extract_csrf(
                page.text
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
    assert response.headers["location"] == (
        "/dashboard/login"
        "?notice=password-changed"
    )

    protected = client.get(
        "/dashboard",
        follow_redirects=False,
    )

    assert protected.status_code == 303

    assert (
        app.state.identity_store.authenticate(
            email=ANALYST_EMAIL,
            password=ANALYST_PASSWORD,
        )
        is None
    )

    assert (
        app.state.identity_store.authenticate(
            email=ANALYST_EMAIL,
            password=NEW_ANALYST_PASSWORD,
        )
        is not None
    )


def test_incorrect_current_password_is_rejected(
    tmp_path,
):
    app = build_app(tmp_path)
    client = TestClient(app)

    login(
        client,
        email=ANALYST_EMAIL,
        password=ANALYST_PASSWORD,
    )

    page = client.get(
        "/dashboard/account/password"
    )

    response = client.post(
        "/dashboard/account/password",
        data={
            "csrf_token": extract_csrf(
                page.text
            ),
            "current_password": (
                "Incorrect-Password-2026!"
            ),
            "new_password": (
                NEW_ANALYST_PASSWORD
            ),
            "new_password_confirmation": (
                NEW_ANALYST_PASSWORD
            ),
        },
    )

    assert response.status_code == 400
    assert (
        "Current password is incorrect"
        in response.text
    )


def test_non_admin_cannot_view_identity_audit(
    tmp_path,
):
    app = build_app(tmp_path)
    client = TestClient(app)

    login(
        client,
        email=ANALYST_EMAIL,
        password=ANALYST_PASSWORD,
    )

    response = client.get(
        "/dashboard/admin/identity-audit"
    )

    assert response.status_code == 403


def test_admin_can_reset_analyst_password(
    tmp_path,
):
    app = build_app(tmp_path)
    client = TestClient(app)

    login(
        client,
        email=ADMIN_EMAIL,
        password=ADMIN_PASSWORD,
    )

    target = (
        app.state.identity_store
        .get_by_email(ANALYST_EMAIL)
    )

    assert target is not None

    admin_page = client.get(
        "/dashboard/admin/analysts"
    )

    response = client.post(
        (
            "/dashboard/admin/analysts/"
            f"{target.user_id}/password-reset"
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

    assert (
        app.state.identity_store.authenticate(
            email=ANALYST_EMAIL,
            password=ANALYST_PASSWORD,
        )
        is None
    )

    assert (
        app.state.identity_store.authenticate(
            email=ANALYST_EMAIL,
            password=RESET_ANALYST_PASSWORD,
        )
        is not None
    )

    events = (
        app.state.identity_store
        .list_audit_events(
            target_user_id=target.user_id
        )
    )

    assert events[0].action == (
        "password_reset"
    )

    assert events[0].actor_email == (
        ADMIN_EMAIL
    )


def test_admin_can_view_identity_audit_without_secrets(
    tmp_path,
):
    app = build_app(tmp_path)
    client = TestClient(app)

    login(
        client,
        email=ADMIN_EMAIL,
        password=ADMIN_PASSWORD,
    )

    target = (
        app.state.identity_store
        .get_by_email(ANALYST_EMAIL)
    )

    admin = (
        app.state.identity_store
        .get_by_email(ADMIN_EMAIL)
    )

    assert target is not None
    assert admin is not None

    app.state.identity_store.reset_password(
        target.user_id,
        new_password=RESET_ANALYST_PASSWORD,
        actor_user_id=admin.user_id,
        actor_email=admin.email,
    )

    response = client.get(
        "/dashboard/admin/identity-audit"
    )

    assert response.status_code == 200
    assert "Password Reset" in response.text
    assert ADMIN_EMAIL in response.text
    assert ANALYST_EMAIL in response.text

    assert (
        RESET_ANALYST_PASSWORD
        not in response.text
    )
