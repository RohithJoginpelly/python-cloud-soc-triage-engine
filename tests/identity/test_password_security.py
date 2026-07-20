"""Password-management and identity-audit tests."""

from __future__ import annotations

import sqlite3

import pytest

from src.identity.store import IdentityStore


CURRENT_PASSWORD = (
    "Secure-Current-Password-2026!"
)

NEW_PASSWORD = (
    "Secure-New-Password-2026!"
)

RESET_PASSWORD = (
    "Secure-Reset-Password-2026!"
)

ADMIN_PASSWORD = (
    "Secure-Admin-Password-2026!"
)


def build_store(tmp_path):
    """Create a store containing an admin and analyst."""

    store = IdentityStore(
        tmp_path / "identity.db"
    )

    admin = store.create_account(
        email="admin@example.com",
        display_name="Admin User",
        password=ADMIN_PASSWORD,
        role="admin",
    )

    analyst = store.create_account(
        email="analyst@example.com",
        display_name="Analyst User",
        password=CURRENT_PASSWORD,
        role="analyst",
    )

    return store, admin, analyst


def test_analyst_can_change_password(
    tmp_path,
):
    store, _, analyst = build_store(
        tmp_path
    )

    store.change_password(
        analyst.user_id,
        current_password=CURRENT_PASSWORD,
        new_password=NEW_PASSWORD,
    )

    assert store.authenticate(
        email=analyst.email,
        password=CURRENT_PASSWORD,
    ) is None

    assert store.authenticate(
        email=analyst.email,
        password=NEW_PASSWORD,
    ) is not None


def test_incorrect_current_password_is_rejected(
    tmp_path,
):
    store, _, analyst = build_store(
        tmp_path
    )

    with pytest.raises(
        ValueError,
        match="Current password is incorrect",
    ):
        store.change_password(
            analyst.user_id,
            current_password=(
                "Incorrect-Password-2026!"
            ),
            new_password=NEW_PASSWORD,
        )

    assert store.authenticate(
        email=analyst.email,
        password=CURRENT_PASSWORD,
    ) is not None


def test_current_password_cannot_be_reused(
    tmp_path,
):
    store, _, analyst = build_store(
        tmp_path
    )

    with pytest.raises(
        ValueError,
        match="must be different",
    ):
        store.change_password(
            analyst.user_id,
            current_password=CURRENT_PASSWORD,
            new_password=CURRENT_PASSWORD,
        )


def test_admin_can_reset_password(
    tmp_path,
):
    store, admin, analyst = build_store(
        tmp_path
    )

    store.reset_password(
        analyst.user_id,
        new_password=RESET_PASSWORD,
        actor_user_id=admin.user_id,
        actor_email=admin.email,
    )

    assert store.authenticate(
        email=analyst.email,
        password=CURRENT_PASSWORD,
    ) is None

    assert store.authenticate(
        email=analyst.email,
        password=RESET_PASSWORD,
    ) is not None


def test_password_change_creates_audit_event(
    tmp_path,
):
    store, _, analyst = build_store(
        tmp_path
    )

    store.change_password(
        analyst.user_id,
        current_password=CURRENT_PASSWORD,
        new_password=NEW_PASSWORD,
    )

    events = store.list_audit_events(
        target_user_id=analyst.user_id
    )

    assert len(events) == 1
    assert events[0].action == (
        "password_changed"
    )
    assert events[0].actor_email == (
        analyst.email
    )
    assert events[0].details == {
        "method": "self_service",
    }


def test_password_reset_records_admin_actor(
    tmp_path,
):
    store, admin, analyst = build_store(
        tmp_path
    )

    store.reset_password(
        analyst.user_id,
        new_password=RESET_PASSWORD,
        actor_user_id=admin.user_id,
        actor_email=admin.email,
    )

    events = store.list_audit_events(
        target_user_id=analyst.user_id
    )

    assert len(events) == 1
    assert events[0].action == (
        "password_reset"
    )
    assert events[0].actor_user_id == (
        admin.user_id
    )
    assert events[0].actor_email == (
        admin.email
    )


def test_audit_log_does_not_store_passwords(
    tmp_path,
):
    database_path = (
        tmp_path / "identity.db"
    )

    store = IdentityStore(
        database_path
    )

    admin = store.create_account(
        email="admin@example.com",
        display_name="Admin User",
        password=ADMIN_PASSWORD,
        role="admin",
    )

    analyst = store.create_account(
        email="analyst@example.com",
        display_name="Analyst User",
        password=CURRENT_PASSWORD,
        role="analyst",
    )

    store.reset_password(
        analyst.user_id,
        new_password=RESET_PASSWORD,
        actor_user_id=admin.user_id,
        actor_email=admin.email,
    )

    with sqlite3.connect(
        database_path
    ) as connection:
        details_json = connection.execute(
            """
            SELECT details_json
            FROM identity_audit_events
            WHERE action = 'password_reset'
            """
        ).fetchone()[0]

    assert RESET_PASSWORD not in details_json
    assert CURRENT_PASSWORD not in details_json
    assert "password_hash" not in details_json
