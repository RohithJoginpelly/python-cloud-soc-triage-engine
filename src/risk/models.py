"""Data models for deterministic SOC risk assessments."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


ALLOWED_RISK_LEVELS = {
    "low",
    "medium",
    "high",
    "critical",
}

ALLOWED_PRIORITIES = {
    "P1",
    "P2",
    "P3",
    "P4",
}


@dataclass(slots=True)
class RiskFactor:
    """One transparent contribution to a risk score."""

    name: str
    points: int
    reason: str

    def __post_init__(self) -> None:
        self.name = self.name.strip()
        self.reason = self.reason.strip()

        if not self.name:
            raise ValueError(
                "Risk factor name is required"
            )

        if self.points < 0:
            raise ValueError(
                "Risk factor points cannot be negative"
            )

        if not self.reason:
            raise ValueError(
                "Risk factor reason is required"
            )


@dataclass(slots=True)
class RiskAssessment:
    """Explainable risk result for one correlation finding."""

    correlation_id: str
    raw_score: int
    risk_score: int
    risk_level: str
    priority: str
    factors: list[RiskFactor] = field(
        default_factory=list
    )

    def __post_init__(self) -> None:
        self.correlation_id = (
            self.correlation_id.strip()
        )
        self.risk_level = (
            self.risk_level.strip().lower()
        )
        self.priority = (
            self.priority.strip().upper()
        )

        if not self.correlation_id:
            raise ValueError(
                "correlation_id is required"
            )

        if self.raw_score < 0:
            raise ValueError(
                "raw_score cannot be negative"
            )

        if not 0 <= self.risk_score <= 100:
            raise ValueError(
                "risk_score must be between 0 and 100"
            )

        if self.risk_level not in ALLOWED_RISK_LEVELS:
            raise ValueError(
                f"Unsupported risk level: {self.risk_level}"
            )

        if self.priority not in ALLOWED_PRIORITIES:
            raise ValueError(
                f"Unsupported priority: {self.priority}"
            )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary."""

        return asdict(self)
