"""Canonical security-event schema for AI SOC Copilot Version 2."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any


ALLOWED_SEVERITIES = {
    "informational",
    "low",
    "medium",
    "high",
    "critical",
}

ALLOWED_OUTCOMES = {
    "success",
    "failure",
    "unknown",
}


def generate_event_id(
    *,
    source_type: str,
    timestamp: str,
    action: str,
    source_ip: str | None = None,
    username: str | None = None,
    raw_event: dict[str, Any] | None = None,
) -> str:
    """Generate a deterministic ID for a normalized security event."""

    identity = {
        "source_type": source_type,
        "timestamp": timestamp,
        "action": action,
        "source_ip": source_ip,
        "username": username,
        "raw_event": raw_event or {},
    }

    canonical_json = json.dumps(
        identity,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )

    digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    return f"evt-{digest[:24]}"


@dataclass(slots=True)
class NormalizedEvent:
    """Vendor-neutral representation of one security event."""

    # Required fields
    timestamp: str
    source_type: str
    source_product: str
    category: str
    action: str

    # Generated automatically when empty
    event_id: str = ""

    # Classification
    outcome: str = "unknown"
    severity: str = "informational"

    # Identity information
    username: str | None = None
    user_id: str | None = None
    user_type: str | None = None
    user_arn: str | None = None

    # Network and host information
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    destination_host: str | None = None

    # Cloud information
    cloud_provider: str | None = None
    cloud_account_id: str | None = None
    cloud_region: str | None = None

    # Detection information
    rule_id: str | None = None
    rule_name: str | None = None
    message: str | None = None

    # Additional evidence
    tags: list[str] = field(default_factory=list)
    raw_event: dict[str, Any] = field(default_factory=dict)

    schema_version: str = "2.0"

    def __post_init__(self) -> None:
        """Validate and standardize values after object creation."""

        self.timestamp = self.timestamp.strip()
        self.source_type = self.source_type.strip().lower()
        self.source_product = self.source_product.strip().lower()
        self.category = self.category.strip().lower()
        self.action = self.action.strip()
        self.outcome = self.outcome.strip().lower()
        self.severity = self.severity.strip().lower()

        if not self.timestamp:
            raise ValueError("timestamp is required")

        if not self.source_type:
            raise ValueError("source_type is required")

        if not self.source_product:
            raise ValueError("source_product is required")

        if not self.category:
            raise ValueError("category is required")

        if not self.action:
            raise ValueError("action is required")

        if self.outcome not in ALLOWED_OUTCOMES:
            raise ValueError(
                f"Invalid outcome: {self.outcome}. "
                f"Allowed outcomes: {sorted(ALLOWED_OUTCOMES)}"
            )

        if self.severity not in ALLOWED_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {self.severity}. "
                f"Allowed severities: {sorted(ALLOWED_SEVERITIES)}"
            )

        if not isinstance(self.raw_event, dict):
            raise TypeError("raw_event must be a dictionary")

        self.tags = list(
            dict.fromkeys(
                tag.strip().lower()
                for tag in self.tags
                if isinstance(tag, str) and tag.strip()
            )
        )

        if not self.event_id:
            self.event_id = generate_event_id(
                source_type=self.source_type,
                timestamp=self.timestamp,
                action=self.action,
                source_ip=self.source_ip,
                username=self.username,
                raw_event=self.raw_event,
            )

    def to_dict(self) -> dict[str, Any]:
        """Return the event as a serializable dictionary."""

        return asdict(self)
