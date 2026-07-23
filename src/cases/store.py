"""SQLite persistence for SOC cases and audit history."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.cases.models import (
    ALLOWED_CASE_STATUSES,
    AuditEvent,
    CaseRecord,
)


def _utc_now() -> str:
    """Return the current UTC time as an ISO string."""

    return datetime.now(timezone.utc).isoformat()


def _to_dictionary(
    value: Any,
    *,
    object_name: str,
) -> dict[str, Any]:
    """Convert supported objects into dictionaries."""

    if isinstance(value, dict):
        return dict(value)

    to_dict = getattr(value, "to_dict", None)

    if callable(to_dict):
        result = to_dict()

        if isinstance(result, dict):
            return result

    raise TypeError(
        f"{object_name} must be a dictionary or "
        "provide a to_dict() method"
    )


def _required_text(
    data: dict[str, Any],
    field_name: str,
) -> str:
    """Read a required nonempty text field."""

    value = data.get(field_name)

    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"{field_name} is required"
        )

    return value.strip()


class SQLiteCaseStore:
    """Store SOC cases and append-only audit events."""

    def __init__(
        self,
        database_path: str | Path,
    ) -> None:
        self.database_path = Path(database_path)

        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.initialize()

    def _connect(self) -> sqlite3.Connection:
        """Open a configured SQLite connection."""

        connection = sqlite3.connect(
            self.database_path
        )

        connection.row_factory = sqlite3.Row
        connection.execute(
            "PRAGMA foreign_keys = ON"
        )

        return connection

    def initialize(self) -> None:
        """Create the database schema when missing."""

        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    correlation_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    priority TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    status TEXT NOT NULL,
                    assigned_to TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    packet_json TEXT NOT NULL,
                    copilot_json TEXT
                );

                CREATE INDEX IF NOT EXISTS
                    idx_cases_status
                ON cases(status);

                CREATE INDEX IF NOT EXISTS
                    idx_cases_priority
                ON cases(priority);

                CREATE INDEX IF NOT EXISTS
                    idx_cases_updated_at
                ON cases(updated_at);

                CREATE TABLE IF NOT EXISTS audit_events (
                    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    FOREIGN KEY(case_id)
                        REFERENCES cases(case_id)
                        ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS
                    idx_audit_case_id
                ON audit_events(case_id);

                CREATE INDEX IF NOT EXISTS
                    idx_audit_created_at
                ON audit_events(created_at);
                """
            )

    def _append_audit(
        self,
        connection: sqlite3.Connection,
        *,
        case_id: str,
        event_type: str,
        actor: str,
        details: dict[str, Any],
        created_at: str | None = None,
    ) -> None:
        """Append one audit event inside a transaction."""

        normalized_actor = actor.strip()

        if not normalized_actor:
            raise ValueError(
                "audit actor is required"
            )

        connection.execute(
            """
            INSERT INTO audit_events (
                case_id,
                event_type,
                actor,
                created_at,
                details_json
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                case_id,
                event_type.strip().lower(),
                normalized_actor,
                created_at or _utc_now(),
                json.dumps(
                    details,
                    sort_keys=True,
                ),
            ),
        )

    def save_packet(
        self,
        packet: Any,
        *,
        actor: str = "system",
    ) -> CaseRecord:
        """Create a case or refresh its triage packet."""

        packet_data = _to_dictionary(
            packet,
            object_name="Triage packet",
        )

        case_id = _required_text(
            packet_data,
            "case_id",
        )

        correlation_id = _required_text(
            packet_data,
            "correlation_id",
        )

        title = _required_text(
            packet_data,
            "title",
        )

        priority = _required_text(
            packet_data,
            "priority",
        ).upper()

        risk_level = _required_text(
            packet_data,
            "risk_level",
        ).lower()

        risk_score = packet_data.get(
            "risk_score"
        )

        if (
            not isinstance(risk_score, int)
            or not 0 <= risk_score <= 100
        ):
            raise ValueError(
                "risk_score must be an integer "
                "between 0 and 100"
            )

        now = _utc_now()

        with self._connect() as connection:
            existing = connection.execute(
                """
                SELECT
                    status,
                    assigned_to,
                    created_at
                FROM cases
                WHERE case_id = ?
                """,
                (case_id,),
            ).fetchone()

            if existing is None:
                status = "new"
                assigned_to = None
                created_at = now
                audit_type = "case_created"
            else:
                status = existing["status"]
                assigned_to = existing[
                    "assigned_to"
                ]
                created_at = existing[
                    "created_at"
                ]
                audit_type = "packet_updated"

            connection.execute(
                """
                INSERT INTO cases (
                    case_id,
                    correlation_id,
                    title,
                    priority,
                    risk_score,
                    risk_level,
                    status,
                    assigned_to,
                    created_at,
                    updated_at,
                    packet_json,
                    copilot_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                ON CONFLICT(case_id) DO UPDATE SET
                    correlation_id = excluded.correlation_id,
                    title = excluded.title,
                    priority = excluded.priority,
                    risk_score = excluded.risk_score,
                    risk_level = excluded.risk_level,
                    updated_at = excluded.updated_at,
                    packet_json = excluded.packet_json
                """,
                (
                    case_id,
                    correlation_id,
                    title,
                    priority,
                    risk_score,
                    risk_level,
                    status,
                    assigned_to,
                    created_at,
                    now,
                    json.dumps(
                        packet_data,
                        sort_keys=True,
                    ),
                ),
            )

            self._append_audit(
                connection,
                case_id=case_id,
                event_type=audit_type,
                actor=actor,
                details={
                    "correlation_id": correlation_id,
                    "priority": priority,
                    "risk_score": risk_score,
                },
                created_at=now,
            )

        record = self.get_case(case_id)

        if record is None:
            raise RuntimeError(
                "Case was not saved successfully"
            )

        return record

    def save_copilot_result(
        self,
        case_id: str,
        result: Any,
        *,
        actor: str = "copilot",
    ) -> CaseRecord:
        """Attach a validated Copilot result to a case."""

        normalized_case_id = case_id.strip()

        if not normalized_case_id:
            raise ValueError(
                "case_id is required"
            )

        result_data = _to_dictionary(
            result,
            object_name="Copilot result",
        )

        now = _utc_now()

        with self._connect() as connection:
            existing = connection.execute(
                """
                SELECT case_id
                FROM cases
                WHERE case_id = ?
                """,
                (normalized_case_id,),
            ).fetchone()

            if existing is None:
                raise KeyError(
                    f"Case not found: {normalized_case_id}"
                )

            connection.execute(
                """
                UPDATE cases
                SET copilot_json = ?,
                    updated_at = ?
                WHERE case_id = ?
                """,
                (
                    json.dumps(
                        result_data,
                        sort_keys=True,
                    ),
                    now,
                    normalized_case_id,
                ),
            )

            self._append_audit(
                connection,
                case_id=normalized_case_id,
                event_type="copilot_result_saved",
                actor=actor,
                details={
                    "provider": result_data.get(
                        "provider"
                    ),
                    "model": result_data.get(
                        "model"
                    ),
                    "prompt_id": result_data.get(
                        "prompt_id"
                    ),
                },
                created_at=now,
            )

        record = self.get_case(
            normalized_case_id
        )

        if record is None:
            raise RuntimeError(
                "Copilot result was not saved"
            )

        return record

    def update_case(
        self,
        case_id: str,
        *,
        status: str | None = None,
        assigned_to: str | None = None,
        note: str | None = None,
        actor: str = "analyst",
    ) -> CaseRecord:
        """Update case workflow fields and audit the change."""

        normalized_case_id = case_id.strip()

        if not normalized_case_id:
            raise ValueError(
                "case_id is required"
            )

        normalized_status: str | None = None

        if status is not None:
            normalized_status = (
                status.strip().lower()
            )

            if (
                normalized_status
                not in ALLOWED_CASE_STATUSES
            ):
                raise ValueError(
                    "Unsupported case status: "
                    f"{normalized_status}"
                )

        normalized_assignment = (
            assigned_to.strip() or None
            if isinstance(assigned_to, str)
            else None
        )

        normalized_note = (
            note.strip()
            if isinstance(note, str)
            else ""
        )

        if (
            normalized_status is None
            and assigned_to is None
            and not normalized_note
        ):
            raise ValueError(
                "At least one case update is required"
            )

        now = _utc_now()

        with self._connect() as connection:
            existing = connection.execute(
                """
                SELECT status, assigned_to
                FROM cases
                WHERE case_id = ?
                """,
                (normalized_case_id,),
            ).fetchone()

            if existing is None:
                raise KeyError(
                    f"Case not found: {normalized_case_id}"
                )

            new_status = (
                normalized_status
                if normalized_status is not None
                else existing["status"]
            )

            new_assignment = (
                normalized_assignment
                if assigned_to is not None
                else existing["assigned_to"]
            )

            connection.execute(
                """
                UPDATE cases
                SET status = ?,
                    assigned_to = ?,
                    updated_at = ?
                WHERE case_id = ?
                """,
                (
                    new_status,
                    new_assignment,
                    now,
                    normalized_case_id,
                ),
            )

            self._append_audit(
                connection,
                case_id=normalized_case_id,
                event_type="case_updated",
                actor=actor,
                details={
                    "previous_status": existing[
                        "status"
                    ],
                    "new_status": new_status,
                    "previous_assigned_to": existing[
                        "assigned_to"
                    ],
                    "new_assigned_to": new_assignment,
                    "note": normalized_note or None,
                },
                created_at=now,
            )

        record = self.get_case(
            normalized_case_id
        )

        if record is None:
            raise RuntimeError(
                "Case update was not saved"
            )

        return record

    def get_case(
        self,
        case_id: str,
    ) -> CaseRecord | None:
        """Read one case by its identifier."""

        normalized_case_id = case_id.strip()

        if not normalized_case_id:
            raise ValueError(
                "case_id is required"
            )

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM cases
                WHERE case_id = ?
                """,
                (normalized_case_id,),
            ).fetchone()

        if row is None:
            return None

        return CaseRecord(
            case_id=row["case_id"],
            correlation_id=row["correlation_id"],
            title=row["title"],
            priority=row["priority"],
            risk_score=row["risk_score"],
            risk_level=row["risk_level"],
            status=row["status"],
            assigned_to=row["assigned_to"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            packet=json.loads(
                row["packet_json"]
            ),
            copilot_result=(
                json.loads(row["copilot_json"])
                if row["copilot_json"]
                else None
            ),
        )

    def list_cases(
        self,
        *,
        status: str | None = None,
        limit: int = 100,
    ) -> list[CaseRecord]:
        """List recent cases, optionally filtered by status."""

        if limit < 1:
            raise ValueError(
                "limit must be at least 1"
            )

        query = """
            SELECT *
            FROM cases
        """

        parameters: list[Any] = []

        if status is not None:
            normalized_status = (
                status.strip().lower()
            )

            if (
                normalized_status
                not in ALLOWED_CASE_STATUSES
            ):
                raise ValueError(
                    "Unsupported case status: "
                    f"{normalized_status}"
                )

            query += " WHERE status = ?"
            parameters.append(
                normalized_status
            )

        query += (
            " ORDER BY updated_at DESC "
            "LIMIT ?"
        )

        parameters.append(limit)

        with self._connect() as connection:
            rows = connection.execute(
                query,
                parameters,
            ).fetchall()

        return [
            CaseRecord(
                case_id=row["case_id"],
                correlation_id=row[
                    "correlation_id"
                ],
                title=row["title"],
                priority=row["priority"],
                risk_score=row["risk_score"],
                risk_level=row["risk_level"],
                status=row["status"],
                assigned_to=row["assigned_to"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                packet=json.loads(
                    row["packet_json"]
                ),
                copilot_result=(
                    json.loads(
                        row["copilot_json"]
                    )
                    if row["copilot_json"]
                    else None
                ),
            )
            for row in rows
        ]

    def get_audit_events(
        self,
        case_id: str,
    ) -> list[AuditEvent]:
        """Return the append-only history for one case."""

        normalized_case_id = case_id.strip()

        if not normalized_case_id:
            raise ValueError(
                "case_id is required"
            )

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM audit_events
                WHERE case_id = ?
                ORDER BY audit_id ASC
                """,
                (normalized_case_id,),
            ).fetchall()

        return [
            AuditEvent(
                audit_id=row["audit_id"],
                case_id=row["case_id"],
                event_type=row["event_type"],
                actor=row["actor"],
                created_at=row["created_at"],
                details=json.loads(
                    row["details_json"]
                ),
            )
            for row in rows
        ]
