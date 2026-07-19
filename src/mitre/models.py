"""Models for evidence-based MITRE ATT&CK mappings."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any


TECHNIQUE_ID_PATTERN = re.compile(
    r"^T\d{4}(?:\.\d{3})?$"
)

ALLOWED_CONFIDENCE_LEVELS = {
    "low",
    "medium",
    "high",
}


@dataclass(slots=True)
class MitreTechnique:
    """One evidence-backed MITRE ATT&CK technique."""

    technique_id: str
    name: str
    tactics: list[str]
    confidence: str
    evidence: str

    def __post_init__(self) -> None:
        self.technique_id = (
            self.technique_id.strip().upper()
        )
        self.name = self.name.strip()
        self.confidence = (
            self.confidence.strip().lower()
        )
        self.evidence = self.evidence.strip()

        if not TECHNIQUE_ID_PATTERN.fullmatch(
            self.technique_id
        ):
            raise ValueError(
                "Invalid MITRE ATT&CK technique ID: "
                f"{self.technique_id}"
            )

        if not self.name:
            raise ValueError(
                "MITRE technique name is required"
            )

        if self.confidence not in (
            ALLOWED_CONFIDENCE_LEVELS
        ):
            raise ValueError(
                "Unsupported MITRE mapping confidence: "
                f"{self.confidence}"
            )

        if not self.evidence:
            raise ValueError(
                "MITRE mapping evidence is required"
            )

        normalized_tactics: list[str] = []

        for tactic in self.tactics:
            if not isinstance(tactic, str):
                continue

            normalized = (
                tactic.strip()
                .lower()
                .replace(" ", "_")
                .replace("-", "_")
            )

            if (
                normalized
                and normalized
                not in normalized_tactics
            ):
                normalized_tactics.append(normalized)

        if not normalized_tactics:
            raise ValueError(
                "At least one MITRE tactic is required"
            )

        self.tactics = normalized_tactics


@dataclass(slots=True)
class MitreMapping:
    """Complete MITRE ATT&CK mapping for one finding."""

    correlation_id: str
    techniques: list[MitreTechnique] = field(
        default_factory=list
    )
    mapping_id: str = field(init=False)
    mapping_version: str = "1.0"

    def __post_init__(self) -> None:
        self.correlation_id = (
            self.correlation_id.strip()
        )

        if not self.correlation_id:
            raise ValueError(
                "correlation_id is required"
            )

        technique_ids = sorted(
            technique.technique_id
            for technique in self.techniques
        )

        fingerprint = json.dumps(
            {
                "correlation_id": self.correlation_id,
                "technique_ids": technique_ids,
                "mapping_version": self.mapping_version,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

        digest = hashlib.sha256(
            fingerprint.encode("utf-8")
        ).hexdigest()

        self.mapping_id = f"mitre-{digest[:16]}"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary."""

        return asdict(self)
