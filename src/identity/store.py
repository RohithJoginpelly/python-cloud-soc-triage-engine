"""Persistent identity storage for SOC analysts."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from src.identity.models import (
    ALLOWED_ANALYST_ROLES,
    AnalystAccount,
    IdentityAuditEvent,
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
        self._initialize_audit_database()

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

    def _initialize_audit_database(
        self,
    ) -> None:
        """Create append-only identity audit storage."""

        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS
                identity_audit_events (
                    event_id TEXT PRIMARY KEY,
                    actor_user_id TEXT,
                    actor_email TEXT NOT NULL,
                    target_user_id TEXT,
                    action TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_identity_audit_target
                ON identity_audit_events(
                    target_user_id,
                    created_at
                )
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_identity_audit_actor
                ON identity_audit_events(
                    actor_user_id,
                    created_at
                )
                """
            )

    @staticmethod
    def _row_to_audit_event(
        row: sqlite3.Row,
    ) -> IdentityAuditEvent:
        """Convert a database row into an audit event."""

        try:
            details = json.loads(
                row["details_json"]
            )
        except (
            json.JSONDecodeError,
            TypeError,
        ):
            details = {}

        if not isinstance(details, dict):
            details = {}

        return IdentityAuditEvent(
            event_id=row["event_id"],
            actor_user_id=row["actor_user_id"],
            actor_email=row["actor_email"],
            target_user_id=row["target_user_id"],
            action=row["action"],
            details=details,
            created_at=row["created_at"],
        )

    @staticmethod
    def _insert_audit_event(
        connection: sqlite3.Connection,
        *,
        actor_user_id: str | None,
        actor_email: str,
        target_user_id: str | None,
        action: str,
        details: dict[str, object] | None = None,
    ) -> str:
        """Insert an identity audit event transactionally."""

        normalized_actor = actor_email.strip().lower()
        normalized_action = action.strip().lower()

        if not normalized_actor:
            raise ValueError(
                "Audit actor email is required."
            )

        if not normalized_action:
            raise ValueError(
                "Audit action is required."
            )

        event_id = str(uuid4())
        timestamp = _utc_now()

        connection.execute(
            """
            INSERT INTO identity_audit_events (
                event_id,
                actor_user_id,
                actor_email,
                target_user_id,
                action,
                details_json,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                actor_user_id,
                normalized_actor,
                target_user_id,
                normalized_action,
                json.dumps(
                    details or {},
                    sort_keys=True,
                ),
                timestamp,
            ),
        )

        return event_id

    def record_audit_event(
        self,
        *,
        actor_user_id: str | None,
        actor_email: str,
        target_user_id: str | None,
        action: str,
        details: dict[str, object] | None = None,
    ) -> IdentityAuditEvent:
        """Record and return an identity audit event."""

        with self._connect() as connection:
            event_id = self._insert_audit_event(
                connection,
                actor_user_id=actor_user_id,
                actor_email=actor_email,
                target_user_id=target_user_id,
                action=action,
                details=details,
            )

            row = connection.execute(
                """
                SELECT
                    event_id,
                    actor_user_id,
                    actor_email,
                    target_user_id,
                    action,
                    details_json,
                    created_at
                FROM identity_audit_events
                WHERE event_id = ?
                """,
                (event_id,),
            ).fetchone()

        if row is None:
            raise RuntimeError(
                "Identity audit event creation failed."
            )

        return self._row_to_audit_event(row)

    def change_password(
        self,
        user_id: str,
        *,
        current_password: str,
        new_password: str,
    ) -> AnalystAccount:
        """Change an analyst's password after verification."""

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    user_id,
                    email,
                    password_hash,
                    is_active
                FROM analyst_accounts
                WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()

            if row is None:
                raise KeyError(
                    f"Unknown account: {user_id}"
                )

            if not bool(row["is_active"]):
                raise ValueError(
                    "Disabled accounts cannot "
                    "change passwords."
                )

            if not verify_password(
                current_password,
                row["password_hash"],
            ):
                raise ValueError(
                    "Current password is incorrect."
                )

            if verify_password(
                new_password,
                row["password_hash"],
            ):
                raise ValueError(
                    "New password must be different "
                    "from the current password."
                )

            new_password_hash = hash_password(
                new_password
            )

            timestamp = _utc_now()

            connection.execute(
                """
                UPDATE analyst_accounts
                SET
                    password_hash = ?,
                    updated_at = ?
                WHERE user_id = ?
                """,
                (
                    new_password_hash,
                    timestamp,
                    user_id,
                ),
            )

            self._insert_audit_event(
                connection,
                actor_user_id=user_id,
                actor_email=row["email"],
                target_user_id=user_id,
                action="password_changed",
                details={
                    "method": "self_service",
                },
            )

        account = self.get_by_id(user_id)

        if account is None:
            raise RuntimeError(
                "Password change failed."
            )

        return account

    def reset_password(
        self,
        user_id: str,
        *,
        new_password: str,
        actor_user_id: str,
        actor_email: str,
    ) -> AnalystAccount:
        """Reset another account's password as an admin."""

        new_password_hash = hash_password(
            new_password
        )

        with self._connect() as connection:
            target = connection.execute(
                """
                SELECT
                    user_id,
                    email
                FROM analyst_accounts
                WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()

            if target is None:
                raise KeyError(
                    f"Unknown account: {user_id}"
                )

            timestamp = _utc_now()

            connection.execute(
                """
                UPDATE analyst_accounts
                SET
                    password_hash = ?,
                    updated_at = ?
                WHERE user_id = ?
                """,
                (
                    new_password_hash,
                    timestamp,
                    user_id,
                ),
            )

            self._insert_audit_event(
                connection,
                actor_user_id=actor_user_id,
                actor_email=actor_email,
                target_user_id=user_id,
                action="password_reset",
                details={
                    "method": "administrator",
                    "target_email": target["email"],
                },
            )

        account = self.get_by_id(user_id)

        if account is None:
            raise RuntimeError(
                "Password reset failed."
            )

        return account

    def list_audit_events(
        self,
        *,
        target_user_id: str | None = None,
        limit: int = 100,
    ) -> list[IdentityAuditEvent]:
        """List recent identity audit events."""

        normalized_limit = max(
            1,
            min(int(limit), 500),
        )

        query = """
            SELECT
                event_id,
                actor_user_id,
                actor_email,
                target_user_id,
                action,
                details_json,
                created_at
            FROM identity_audit_events
        """

        parameters: list[object] = []

        if target_user_id is not None:
            query += """
                WHERE target_user_id = ?
            """

            parameters.append(
                target_user_id
            )

        query += """
            ORDER BY created_at DESC, event_id DESC
            LIMIT ?
        """

        parameters.append(normalized_limit)

        with self._connect() as connection:
            rows = connection.execute(
                query,
                parameters,
            ).fetchall()

        return [
            self._row_to_audit_event(row)
            for row in rows
        ]
