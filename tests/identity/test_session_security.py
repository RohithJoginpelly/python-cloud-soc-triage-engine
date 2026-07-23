"""Tests for server-side analyst session security."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from src.identity.session_security import (
    SessionSecurityStore,
)


USER_ID = "analyst-user-id"

BASE_TIME = datetime(
    2026,
    7,
    22,
    12,
    0,
    0,
    tzinfo=timezone.utc,
)


def build_store(tmp_path):
    """Create an isolated session store."""

    return SessionSecurityStore(
        tmp_path / "sessions.db",
        idle_timeout_minutes=30,
        absolute_timeout_hours=8,
    )


def test_each_login_creates_unique_session_id(
    tmp_path,
):
    store = build_store(tmp_path)

    first = store.create_session(
        USER_ID,
        now=BASE_TIME,
    )

    second = store.create_session(
        USER_ID,
        now=BASE_TIME,
    )

    assert first.session_id != second.session_id
    assert first.user_id == USER_ID
    assert second.user_id == USER_ID


def test_active_session_is_validated_and_touched(
    tmp_path,
):
    store = build_store(tmp_path)

    session = store.create_session(
        USER_ID,
        now=BASE_TIME,
    )

    activity_time = (
        BASE_TIME
        + timedelta(minutes=10)
    )

    validated = store.validate_and_touch(
        session.session_id,
        now=activity_time,
    )

    assert validated is not None

    assert validated.last_seen_at == (
        activity_time.isoformat()
    )

    assert validated.is_revoked is False


def test_idle_session_expires(
    tmp_path,
):
    store = build_store(tmp_path)

    session = store.create_session(
        USER_ID,
        now=BASE_TIME,
    )

    expired = store.validate_and_touch(
        session.session_id,
        now=(
            BASE_TIME
            + timedelta(minutes=31)
        ),
    )

    assert expired is None

    stored = store.get_session(
        session.session_id
    )

    assert stored is not None
    assert stored.is_revoked is True


def test_absolute_session_lifetime_is_enforced(
    tmp_path,
):
    store = build_store(tmp_path)

    session = store.create_session(
        USER_ID,
        now=BASE_TIME,
    )

    active = store.validate_and_touch(
        session.session_id,
        now=(
            BASE_TIME
            + timedelta(minutes=29)
        ),
    )

    assert active is not None

    expired = store.validate_and_touch(
        session.session_id,
        now=(
            BASE_TIME
            + timedelta(
                hours=8,
                seconds=1,
            )
        ),
    )

    assert expired is None


def test_revoked_session_is_rejected(
    tmp_path,
):
    store = build_store(tmp_path)

    session = store.create_session(
        USER_ID,
        now=BASE_TIME,
    )

    changed = store.revoke_session(
        session.session_id,
        now=(
            BASE_TIME
            + timedelta(minutes=5)
        ),
    )

    assert changed is True

    assert (
        store.validate_and_touch(
            session.session_id,
            now=(
                BASE_TIME
                + timedelta(minutes=6)
            ),
        )
        is None
    )


def test_all_user_sessions_can_be_revoked(
    tmp_path,
):
    store = build_store(tmp_path)

    first = store.create_session(
        USER_ID,
        now=BASE_TIME,
    )

    second = store.create_session(
        USER_ID,
        now=BASE_TIME,
    )

    revoked_count = (
        store.revoke_user_sessions(
            USER_ID,
            now=(
                BASE_TIME
                + timedelta(minutes=2)
            ),
        )
    )

    assert revoked_count == 2

    assert (
        store.validate_and_touch(
            first.session_id,
            now=(
                BASE_TIME
                + timedelta(minutes=3)
            ),
        )
        is None
    )

    assert (
        store.validate_and_touch(
            second.session_id,
            now=(
                BASE_TIME
                + timedelta(minutes=3)
            ),
        )
        is None
    )
