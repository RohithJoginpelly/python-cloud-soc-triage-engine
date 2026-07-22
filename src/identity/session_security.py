"""Server-side session management for SOC analysts."""

from __future__ import annotations

import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


DEFAULT_IDLE_TIMEOUT_MINUTES = 30
DEFAULT_ABSOLUTE_TIMEOUT_HOURS = 8


def _utc_now() -> datetime:
    """Return the current timezone-aware UTC time."""

    return datetime.now(timezone.utc)


def _normalize_now(
    value: datetime | None,
) -> datetime:
    """Normalize a supplied time to timezone-aware UTC."""

    if value is None:
        return _utc_now()

    if value.tzinfo is None:
        value = value.replace(
            tzinfo=timezone.utc
        )

    return value.astimezone(timezone.utc)


def _parse_timestamp(
    value: str,
) -> datetime:
    """Parse a stored ISO-8601 timestamp."""

    normalized = value

    if normalized.endswith("Z"):
        normalized = (
            normalized[:-1]
            + "+00:00"
        )

    parsed = datetime.fromisoformat(
        normalized
    )

    if parsed.tzinfo is None:
        parsed = parsed.replace(
            tzinfo=timezone.utc
        )

    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class AnalystSession:
    """Persistent authenticated analyst session."""

    session_id: str
    user_id: str
    created_at: str
    last_seen_at: str
    absolute_expires_at: str
    idle_timeout_seconds: int
    revoked_at: str | None = None

    @property
    def is_revoked(self) -> bool:
        """Return whether the session was revoked."""

        return self.revoked_at is not None

    def idle_expired(
        self,
        *,
        now: datetime,
    ) -> bool:
        """Return whether inactivity exceeded the limit."""

        last_seen = _parse_timestamp(
            self.last_seen_at
        )

        expiration = (
            last_seen
            + timedelta(
                seconds=self.idle_timeout_seconds
            )
        )

        return now >= expiration

    def absolute_expired(
        self,
        *,
        now: datetime,
    ) -> bool:
        """Return whether the absolute lifetime ended."""

        expiration = _parse_timestamp(
            self.absolute_expires_at
        )

        return now >= expiration


class SessionSecurityStore:
    """SQLite-backed analyst session repository."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        idle_timeout_minutes: int = (
            DEFAULT_IDLE_TIMEOUT_MINUTES
        ),
        absolute_timeout_hours: int = (
            DEFAULT_ABSOLUTE_TIMEOUT_HOURS
        ),
    ) -> None:
        if idle_timeout_minutes < 1:
            raise ValueError(
                "idle_timeout_minutes must be "
                "at least one."
            )

        if absolute_timeout_hours < 1:
            raise ValueError(
                "absolute_timeout_hours must be "
                "at least one."
            )

        self.database_path = Path(
            database_path
        )

        self.idle_timeout_seconds = (
            idle_timeout_minutes * 60
        )

        self.absolute_timeout_hours = (
            absolute_timeout_hours
        )

        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._initialize_database()

    def _connect(
        self,
    ) -> sqlite3.Connection:
        """Open a configured SQLite connection."""

        connection = sqlite3.connect(
            self.database_path
        )

        connection.row_factory = sqlite3.Row

        return connection

    def _initialize_database(
        self,
    ) -> None:
        """Create persistent session storage."""

        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS
                analyst_sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    absolute_expires_at TEXT NOT NULL,
                    idle_timeout_seconds INTEGER
                        NOT NULL,
                    revoked_at TEXT
                )
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_analyst_sessions_user
                ON analyst_sessions(
                    user_id,
                    revoked_at
                )
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_analyst_sessions_expiration
                ON analyst_sessions(
                    absolute_expires_at
                )
                """
            )

    @staticmethod
    def _row_to_session(
        row: sqlite3.Row,
    ) -> AnalystSession:
        """Convert a database row into a session."""

        return AnalystSession(
            session_id=row["session_id"],
            user_id=row["user_id"],
            created_at=row["created_at"],
            last_seen_at=row["last_seen_at"],
            absolute_expires_at=(
                row["absolute_expires_at"]
            ),
            idle_timeout_seconds=int(
                row["idle_timeout_seconds"]
            ),
            revoked_at=row["revoked_at"],
        )

    def create_session(
        self,
        user_id: str,
        *,
        now: datetime | None = None,
    ) -> AnalystSession:
        """Create a new rotated session identifier."""

        normalized_user_id = user_id.strip()

        if not normalized_user_id:
            raise ValueError(
                "A user identifier is required."
            )

        current_time = _normalize_now(now)

        session_id = secrets.token_urlsafe(
            32
        )

        created_at = current_time.isoformat()

        absolute_expires_at = (
            current_time
            + timedelta(
                hours=self.absolute_timeout_hours
            )
        ).isoformat()

        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO analyst_sessions (
                    session_id,
                    user_id,
                    created_at,
                    last_seen_at,
                    absolute_expires_at,
                    idle_timeout_seconds,
                    revoked_at
                )
                VALUES (?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    session_id,
                    normalized_user_id,
                    created_at,
                    created_at,
                    absolute_expires_at,
                    self.idle_timeout_seconds,
                ),
            )

        session = self.get_session(
            session_id
        )

        if session is None:
            raise RuntimeError(
                "Session creation failed."
            )

        return session

    def get_session(
        self,
        session_id: str,
    ) -> AnalystSession | None:
        """Retrieve a session by identifier."""

        if not isinstance(session_id, str):
            return None

        normalized_session_id = (
            session_id.strip()
        )

        if not normalized_session_id:
            return None

        with self._connect() as connection:
            row = connection.execute(
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
                WHERE session_id = ?
                """,
                (normalized_session_id,),
            ).fetchone()

        if row is None:
            return None

        return self._row_to_session(row)

    def validate_and_touch(
        self,
        session_id: str,
        *,
        now: datetime | None = None,
    ) -> AnalystSession | None:
        """Validate a session and refresh activity time."""

        session = self.get_session(
            session_id
        )

        if session is None:
            return None

        if session.is_revoked:
            return None

        current_time = _normalize_now(now)

        if (
            session.idle_expired(now=current_time)
            or session.absolute_expired(
                now=current_time
            )
        ):
            self.revoke_session(
                session.session_id,
                now=current_time,
            )

            return None

        last_seen_at = current_time.isoformat()

        with self._connect() as connection:
            connection.execute(
                """
                UPDATE analyst_sessions
                SET last_seen_at = ?
                WHERE
                    session_id = ?
                    AND revoked_at IS NULL
                """,
                (
                    last_seen_at,
                    session.session_id,
                ),
            )

        return self.get_session(
            session.session_id
        )

    def revoke_session(
        self,
        session_id: str,
        *,
        now: datetime | None = None,
    ) -> bool:
        """Revoke one active session."""

        current_time = _normalize_now(now)

        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE analyst_sessions
                SET revoked_at = ?
                WHERE
                    session_id = ?
                    AND revoked_at IS NULL
                """,
                (
                    current_time.isoformat(),
                    session_id,
                ),
            )

            changed = cursor.rowcount > 0

        return changed

    def revoke_user_sessions(
        self,
        user_id: str,
        *,
        now: datetime | None = None,
    ) -> int:
        """Revoke every active session for a user."""

        current_time = _normalize_now(now)

        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE analyst_sessions
                SET revoked_at = ?
                WHERE
                    user_id = ?
                    AND revoked_at IS NULL
                """,
                (
                    current_time.isoformat(),
                    user_id,
                ),
            )

            revoked_count = cursor.rowcount

        return revoked_count
