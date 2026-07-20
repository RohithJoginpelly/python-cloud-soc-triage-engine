import sqlite3

import pytest

from src.identity.passwords import (
    hash_password,
    verify_password,
)
from src.identity.store import (
    IdentityStore,
)


TEST_PASSWORD = (
    "Secure-Test-Password-2026!"
)


def test_password_hash_does_not_store_plaintext():
    encoded = hash_password(
        TEST_PASSWORD
    )

    assert TEST_PASSWORD not in encoded
    assert encoded.startswith("scrypt$")
    assert verify_password(
        TEST_PASSWORD,
        encoded,
    )
    assert not verify_password(
        "incorrect-password",
        encoded,
    )


def test_short_password_is_rejected():
    with pytest.raises(
        ValueError,
        match="at least 12",
    ):
        hash_password("too-short")


def test_create_and_retrieve_account(
    tmp_path,
):
    store = IdentityStore(
        tmp_path / "identity.db"
    )

    account = store.create_account(
        email="Alice@Example.com",
        display_name="Alice Analyst",
        password=TEST_PASSWORD,
        role="analyst",
    )

    assert account.email == (
        "alice@example.com"
    )
    assert account.display_name == (
        "Alice Analyst"
    )
    assert account.role == "analyst"
    assert account.is_active is True

    retrieved = store.get_by_email(
        "ALICE@example.com"
    )

    assert retrieved == account


def test_duplicate_email_is_rejected(
    tmp_path,
):
    store = IdentityStore(
        tmp_path / "identity.db"
    )

    store.create_account(
        email="alice@example.com",
        display_name="Alice",
        password=TEST_PASSWORD,
    )

    with pytest.raises(
        ValueError,
        match="already exists",
    ):
        store.create_account(
            email="ALICE@example.com",
            display_name="Second Alice",
            password=TEST_PASSWORD,
        )


def test_valid_credentials_authenticate(
    tmp_path,
):
    store = IdentityStore(
        tmp_path / "identity.db"
    )

    store.create_account(
        email="alice@example.com",
        display_name="Alice",
        password=TEST_PASSWORD,
    )

    authenticated = store.authenticate(
        email="alice@example.com",
        password=TEST_PASSWORD,
    )

    assert authenticated is not None
    assert authenticated.last_login_at is not None


def test_invalid_password_is_rejected(
    tmp_path,
):
    store = IdentityStore(
        tmp_path / "identity.db"
    )

    store.create_account(
        email="alice@example.com",
        display_name="Alice",
        password=TEST_PASSWORD,
    )

    authenticated = store.authenticate(
        email="alice@example.com",
        password="Wrong-Password-2026!",
    )

    assert authenticated is None


def test_disabled_account_cannot_login(
    tmp_path,
):
    store = IdentityStore(
        tmp_path / "identity.db"
    )

    account = store.create_account(
        email="alice@example.com",
        display_name="Alice",
        password=TEST_PASSWORD,
    )

    disabled = store.set_active(
        account.user_id,
        is_active=False,
    )

    assert disabled.is_active is False

    authenticated = store.authenticate(
        email="alice@example.com",
        password=TEST_PASSWORD,
    )

    assert authenticated is None


def test_role_can_be_changed(
    tmp_path,
):
    store = IdentityStore(
        tmp_path / "identity.db"
    )

    account = store.create_account(
        email="alice@example.com",
        display_name="Alice",
        password=TEST_PASSWORD,
    )

    updated = store.update_role(
        account.user_id,
        role="senior_analyst",
    )

    assert updated.role == (
        "senior_analyst"
    )


def test_invalid_role_is_rejected(
    tmp_path,
):
    store = IdentityStore(
        tmp_path / "identity.db"
    )

    with pytest.raises(
        ValueError,
        match="Unsupported analyst role",
    ):
        store.create_account(
            email="alice@example.com",
            display_name="Alice",
            password=TEST_PASSWORD,
            role="superuser",
        )


def test_database_contains_password_hash(
    tmp_path,
):
    database_path = (
        tmp_path / "identity.db"
    )

    store = IdentityStore(
        database_path
    )

    store.create_account(
        email="alice@example.com",
        display_name="Alice",
        password=TEST_PASSWORD,
    )

    with sqlite3.connect(
        database_path
    ) as connection:
        stored_hash = connection.execute(
            """
            SELECT password_hash
            FROM analyst_accounts
            WHERE email = ?
            """,
            ("alice@example.com",),
        ).fetchone()[0]

    assert TEST_PASSWORD not in stored_hash
    assert verify_password(
        TEST_PASSWORD,
        stored_hash,
    )
