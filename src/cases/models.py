"""Models for persistent SOC case management."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


ALLOWED_CASE_STATUSES = {
    "new",
    "triage",
    "investigating",
    "contained",
    "resolved",
    "closed",
    "false_positive",
}


@dataclass(slots=True)
class CaseRecord:
    """Persistent representation of one SOC case."""

    case_id: str
    correlation_id: str
    title: str

    priority: str
    risk_score: int
    risk_level: str

    status: str
    created_at: str
    updated_at: str

    assigned_to: str | None = None
    packet: dict[str, Any] = field(
        default_factory=dict
    )
    copilot_result: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        self.case_id = self.case_id.strip()
        self.correlation_id = self.correlation_id.strip()
        self.title = self.title.strip()
        self.priority = self.priority.strip().upper()
        self.risk_level = self.risk_level.strip().lower()
        self.status = self.status.strip().lower()
        self.created_at = self.created_at.strip()
        self.updated_at = self.updated_at.strip()

        if isinstance(self.assigned_to, str):
            self.assigned_to = (
                self.assigned_to.strip() or None
            )

        if not self.case_id:
            raise ValueError("case_id is required")

        if not self.correlation_id:
            raise ValueError(
                "correlation_id is required"
            )

        if not self.title:
            raise ValueError("case title is required")

        if not 0 <= self.risk_score <= 100:
            raise ValueError(
                "risk_score must be between 0 and 100"
            )

        if self.status not in ALLOWED_CASE_STATUSES:
            raise ValueError(
                f"Unsupported case status: {self.status}"
            )

        if not isinstance(self.packet, dict):
            raise TypeError(
                "packet must be a dictionary"
            )

        if (
            self.copilot_result is not None
            and not isinstance(
                self.copilot_result,
                dict,
            )
        ):
            raise TypeError(
                "copilot_result must be a dictionary or None"
            )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable case dictionary."""

        return asdict(self)


@dataclass(slots=True)
class AuditEvent:
    """One append-only case audit event."""

    audit_id: int
    case_id: str
    event_type: str
    actor: str
    created_at: str
    details: dict[str, Any] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        self.case_id = self.case_id.strip()
        self.event_type = self.event_type.strip().lower()
        self.actor = self.actor.strip()
        self.created_at = self.created_at.strip()

        if self.audit_id < 1:
            raise ValueError(
                "audit_id must be positive"
            )

        if not self.case_id:
            raise ValueError(
                "audit case_id is required"
            )

        if not self.event_type:
            raise ValueError(
                "audit event_type is required"
            )

        if not self.actor:
            raise ValueError(
                "audit actor is required"
            )

        if not isinstance(self.details, dict):
            raise TypeError(
                "audit details must be a dictionary"
            )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable audit dictionary."""

        return asdict(self)
