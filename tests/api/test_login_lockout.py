"""Dashboard login lockout integration tests."""

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

TEST_EMAIL = "analyst@example.com"
TEST_PASSWORD = (
    "Secure-Analyst-Password-2026!"
)

WRONG_PASSWORD = (
    "Incorrect-Password-2026!"
)


def build_app(tmp_path):
    """Create an isolated application."""

    app = create_app(
        database_path=tmp_path / "cases.db",
        input_root=INPUT_ROOT,
        api_key="lockout-api-test-key",
        session_secret=(
            "lockout-session-test-secret"
        ),
    )

    app.state.identity_store.create_account(
        email=TEST_EMAIL,
        display_name="Analyst User",
        password=TEST_PASSWORD,
        role="analyst",
    )

    return app


def extract_csrf(html: str) -> str:
    """Extract a CSRF token from rendered HTML."""

    match = re.search(
        r'name="csrf_token"\s+'
        r'value="([^"]+)"',
        html,
    )

    assert match is not None

    return match.group(1)


def submit_login(
    client: TestClient,
    *,
    password: str,
):
    """Submit one login attempt."""

    login_page = client.get(
        "/dashboard/login"
    )

    assert login_page.status_code == 200

    return client.post(
        "/dashboard/login",
        data={
            "email": TEST_EMAIL,
            "password": password,
            "csrf_token": extract_csrf(
                login_page.text
            ),
        },
        follow_redirects=False,
    )


def test_account_locks_after_five_failures(
    tmp_path,
):
    app = build_app(tmp_path)
    client = TestClient(app)

    for attempt in range(1, 6):
        response = submit_login(
            client,
            password=WRONG_PASSWORD,
        )

        assert response.status_code == 401

        if attempt < 5:
            assert (
                "Invalid email or password"
                in response.text
            )
        else:
            assert (
                "Too many failed attempts"
                in response.text
            )

    state = (
        app.state.login_security_store
        .get_state(TEST_EMAIL)
    )

    assert state is not None
    assert state.failed_attempts == 5
    assert state.is_locked is True

    correct_password_response = submit_login(
        client,
        password=TEST_PASSWORD,
    )

    assert (
        correct_password_response.status_code
        == 401
    )

    assert (
        "Too many failed attempts"
        in correct_password_response.text
    )

    events = (
        app.state.identity_store
        .list_audit_events(limit=20)
    )

    actions = [
        event.action
        for event in events
    ]

    assert "account_locked" in actions
    assert "login_blocked" in actions


def test_successful_login_resets_failures(
    tmp_path,
):
    app = build_app(tmp_path)
    client = TestClient(app)

    failed_response = submit_login(
        client,
        password=WRONG_PASSWORD,
    )

    assert failed_response.status_code == 401

    success_response = submit_login(
        client,
        password=TEST_PASSWORD,
    )

    assert success_response.status_code == 303
    assert success_response.headers[
        "location"
    ] == "/dashboard"

    state = (
        app.state.login_security_store
        .get_state(TEST_EMAIL)
    )

    assert state is not None
    assert state.failed_attempts == 0
    assert state.locked_until is None
    assert state.is_locked is False

    events = (
        app.state.identity_store
        .list_audit_events(limit=20)
    )

    assert any(
        event.action == "login_succeeded"
        for event in events
    )
