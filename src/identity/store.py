"""Persistent identity storage for SOC analysts."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from src.identity.models import (
    ALLOWED_ANALYST_ROLES,
    AnalystAccount,
)
from src.identity.passwords import (
    hash_password,
    verify_password,
)


def _utc_now() -> str:
    """Return a timezone-aware UTC timestamp."""

    return datetime.now(
        timezone.utc
    ).isoformat()


def _normalize_email(email: str) -> str:
    """Normalize and validate an email address."""

    normalized = email.strip().lower()

    if (
        not normalized
        or "@" not in normalized
        or normalized.startswith("@")
        or normalized.endswith("@")
    ):
        raise ValueError(
            "A valid email address is required."
        )

    return normalized


class IdentityStore:
    """SQLite-backed analyst account repository."""

    def __init__(
        self,
        database_path: str | Path,
    ) -> None:
        self.database_path = Path(
            database_path
        )

        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._initialize_database()

    def _connect(
        self,
    ) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database_path
        )

        connection.row_factory = (
            sqlite3.Row
        )

        return connection

    def _initialize_database(
        self,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS
                analyst_accounts (
                    user_id TEXT PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE
                        COLLATE NOCASE,
                    display_name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    is_active INTEGER NOT NULL
                        DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_login_at TEXT
                )
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_analyst_accounts_email
                ON analyst_accounts(email)
                """
            )

    @staticmethod
    def _row_to_account(
        row: sqlite3.Row,
    ) -> AnalystAccount:
        return AnalystAccount(
            user_id=row["user_id"],
            email=row["email"],
            display_name=(
                row["display_name"]
            ),
            role=row["role"],
            is_active=bool(
                row["is_active"]
            ),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            last_login_at=(
                row["last_login_at"]
            ),
        )

    def create_account(
        self,
        *,
        email: str,
        display_name: str,
        password: str,
        role: str = "analyst",
    ) -> AnalystAccount:
        """Create an individual analyst account."""

        normalized_email = (
            _normalize_email(email)
        )

        normalized_name = (
            display_name.strip()
        )

        normalized_role = (
            role.strip().lower()
        )

        if not normalized_name:
            raise ValueError(
                "Display name is required."
            )

        if normalized_role not in (
            ALLOWED_ANALYST_ROLES
        ):
            raise ValueError(
                f"Unsupported analyst role: "
                f"{role}"
            )

        password_hash = hash_password(
            password
        )

        user_id = str(uuid4())
        timestamp = _utc_now()

        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO analyst_accounts (
                        user_id,
                        email,
                        display_name,
                        role,
                        password_hash,
                        is_active,
                        created_at,
                        updated_at,
                        last_login_at
                    )
                    VALUES (?, ?, ?, ?, ?, 1, ?, ?, NULL)
                    """,
                    (
                        user_id,
                        normalized_email,
                        normalized_name,
                        normalized_role,
                        password_hash,
                        timestamp,
                        timestamp,
                    ),
                )
        except sqlite3.IntegrityError as error:
            raise ValueError(
                "An account already exists "
                "for this email."
            ) from error

        account = self.get_by_id(
            user_id
        )

        if account is None:
            raise RuntimeError(
                "Account creation failed."
            )

        return account

    def get_by_id(
        self,
        user_id: str,
    ) -> AnalystAccount | None:
        """Retrieve an account by user identifier."""

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    user_id,
                    email,
                    display_name,
                    role,
                    is_active,
                    created_at,
                    updated_at,
                    last_login_at
                FROM analyst_accounts
                WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()

        if row is None:
            return None

        return self._row_to_account(row)

    def get_by_email(
        self,
        email: str,
    ) -> AnalystAccount | None:
        """Retrieve an account by normalized email."""

        try:
            normalized_email = (
                _normalize_email(email)
            )
        except ValueError:
            return None

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    user_id,
                    email,
                    display_name,
                    role,
                    is_active,
                    created_at,
                    updated_at,
                    last_login_at
                FROM analyst_accounts
                WHERE email = ?
                """,
                (normalized_email,),
            ).fetchone()

        if row is None:
            return None

        return self._row_to_account(row)

    def authenticate(
        self,
        *,
        email: str,
        password: str,
    ) -> AnalystAccount | None:
        """Authenticate an active analyst account."""

        try:
            normalized_email = (
                _normalize_email(email)
            )
        except ValueError:
            return None

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    user_id,
                    email,
                    display_name,
                    role,
                    password_hash,
                    is_active,
                    created_at,
                    updated_at,
                    last_login_at
                FROM analyst_accounts
                WHERE email = ?
                """,
                (normalized_email,),
            ).fetchone()

            if row is None:
                return None

            if not bool(row["is_active"]):
                return None

            if not verify_password(
                password,
                row["password_hash"],
            ):
                return None

            login_timestamp = _utc_now()

            connection.execute(
                """
                UPDATE analyst_accounts
                SET
                    last_login_at = ?,
                    updated_at = ?
                WHERE user_id = ?
                """,
                (
                    login_timestamp,
                    login_timestamp,
                    row["user_id"],
                ),
            )

        return self.get_by_id(
            row["user_id"]
        )

    def set_active(
        self,
        user_id: str,
        *,
        is_active: bool,
    ) -> AnalystAccount:
        """Enable or disable an analyst account."""

        timestamp = _utc_now()

        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE analyst_accounts
                SET
                    is_active = ?,
                    updated_at = ?
                WHERE user_id = ?
                """,
                (
                    int(is_active),
                    timestamp,
                    user_id,
                ),
            )

        if cursor.rowcount == 0:
            raise KeyError(
                f"Unknown account: {user_id}"
            )

        account = self.get_by_id(
            user_id
        )

        if account is None:
            raise RuntimeError(
                "Account update failed."
            )

        return account

    def update_role(
        self,
        user_id: str,
        *,
        role: str,
    ) -> AnalystAccount:
        """Change an analyst account role."""

        normalized_role = (
            role.strip().lower()
        )

        if normalized_role not in (
            ALLOWED_ANALYST_ROLES
        ):
            raise ValueError(
                f"Unsupported analyst role: "
                f"{role}"
            )

        timestamp = _utc_now()

        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE analyst_accounts
                SET
                    role = ?,
                    updated_at = ?
                WHERE user_id = ?
                """,
                (
                    normalized_role,
                    timestamp,
                    user_id,
                ),
            )

        if cursor.rowcount == 0:
            raise KeyError(
                f"Unknown account: {user_id}"
            )

        account = self.get_by_id(
            user_id
        )

        if account is None:
            raise RuntimeError(
                "Role update failed."
            )

        return account

    def list_accounts(
        self,
    ) -> list[AnalystAccount]:
        """List all analyst accounts."""

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    user_id,
                    email,
                    display_name,
                    role,
                    is_active,
                    created_at,
                    updated_at,
                    last_login_at
                FROM analyst_accounts
                ORDER BY email ASC
                """
            ).fetchall()

        return [
            self._row_to_account(row)
            for row in rows
        ]
