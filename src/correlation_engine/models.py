"""Data models for SOC Copilot Version 2 correlation findings."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any


ALLOWED_CORRELATION_SEVERITIES = {
    "informational",
    "low",
    "medium",
    "high",
    "critical",
}


def generate_correlation_id(
    *,
    rule_id: str,
    event_ids: list[str],
) -> str:
    """Generate a deterministic identifier for a correlation finding."""

    identity = {
        "rule_id": rule_id,
        "event_ids": sorted(event_ids),
    }

    canonical_json = json.dumps(
        identity,
        sort_keys=True,
        separators=(",", ":"),
    )

    digest = hashlib.sha256(
        canonical_json.encode("utf-8")
    ).hexdigest()

    return f"corr-{digest[:24]}"


@dataclass(slots=True)
class CorrelationFinding:
    """A security finding produced from multiple related events."""

    rule_id: str
    title: str
    description: str
    severity: str
    confidence: float
    category: str

    first_seen: str
    last_seen: str
    event_ids: list[str]

    source_products: list[str] = field(
        default_factory=list
    )

    source_ip: str | None = None
    username: str | None = None
    destination_host: str | None = None

    evidence_summary: str | None = None
    recommended_action: str | None = None
    tags: list[str] = field(default_factory=list)

    correlation_id: str = ""
    schema_version: str = "2.0"

    def __post_init__(self) -> None:
        """Validate and standardize the finding."""

        self.rule_id = self.rule_id.strip()
        self.title = self.title.strip()
        self.description = self.description.strip()
        self.severity = self.severity.strip().lower()
        self.category = self.category.strip().lower()

        if not self.rule_id:
            raise ValueError("rule_id is required")

        if not self.title:
            raise ValueError("title is required")

        if not self.description:
            raise ValueError("description is required")

        if self.severity not in ALLOWED_CORRELATION_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {self.severity}"
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "confidence must be between 0.0 and 1.0"
            )

        if not self.first_seen:
            raise ValueError("first_seen is required")

        if not self.last_seen:
            raise ValueError("last_seen is required")

        if not self.event_ids:
            raise ValueError(
                "At least one event_id is required"
            )

        self.event_ids = list(
            dict.fromkeys(self.event_ids)
        )

        self.source_products = sorted(
            {
                product.strip().lower()
                for product in self.source_products
                if isinstance(product, str)
                and product.strip()
            }
        )

        self.tags = list(
            dict.fromkeys(
                tag.strip().lower()
                for tag in self.tags
                if isinstance(tag, str)
                and tag.strip()
            )
        )

        if not self.correlation_id:
            self.correlation_id = (
                generate_correlation_id(
                    rule_id=self.rule_id,
                    event_ids=self.event_ids,
                )
            )

    def to_dict(self) -> dict[str, Any]:
        """Return a serializable dictionary."""

        return asdict(self)
