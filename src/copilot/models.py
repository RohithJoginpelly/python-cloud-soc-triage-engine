"""Models for evidence-grounded AI SOC Copilot interactions."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class CopilotPrompt:
    """Auditable prompt created from one triage packet."""

    case_id: str
    text: str
    prompt_id: str = field(init=False)
    prompt_version: str = "1.0"

    def __post_init__(self) -> None:
        self.case_id = self.case_id.strip()
        self.text = self.text.strip()

        if not self.case_id:
            raise ValueError(
                "case_id is required"
            )

        if not self.text:
            raise ValueError(
                "Copilot prompt text is required"
            )

        fingerprint = (
            f"{self.case_id}|"
            f"{self.prompt_version}|"
            f"{self.text}"
        )

        digest = hashlib.sha256(
            fingerprint.encode("utf-8")
        ).hexdigest()

        self.prompt_id = f"prompt-{digest[:16]}"

    def to_dict(self) -> dict[str, Any]:
        """Return a serializable prompt dictionary."""

        return asdict(self)


@dataclass(slots=True)
class CopilotDraft:
    """Structured draft returned by an AI model."""

    executive_summary: str
    assessment: str

    key_observations: list[str]
    investigation_steps: list[str]
    containment_considerations: list[str]

    cited_event_ids: list[str]
    cited_mitre_techniques: list[str]

    uncertainties: list[str] = field(
        default_factory=list
    )

    draft_version: str = "1.0"

    def __post_init__(self) -> None:
        self.executive_summary = (
            self.executive_summary.strip()
        )
        self.assessment = self.assessment.strip()

        if not self.executive_summary:
            raise ValueError(
                "executive_summary is required"
            )

        if not self.assessment:
            raise ValueError(
                "assessment is required"
            )

        self.key_observations = (
            self._normalize_list(
                self.key_observations
            )
        )

        self.investigation_steps = (
            self._normalize_list(
                self.investigation_steps
            )
        )

        self.containment_considerations = (
            self._normalize_list(
                self.containment_considerations
            )
        )

        self.cited_event_ids = (
            self._normalize_list(
                self.cited_event_ids
            )
        )

        self.cited_mitre_techniques = (
            self._normalize_list(
                self.cited_mitre_techniques,
                uppercase=True,
            )
        )

        self.uncertainties = self._normalize_list(
            self.uncertainties
        )

        if not self.key_observations:
            raise ValueError(
                "At least one key observation is required"
            )

        if not self.investigation_steps:
            raise ValueError(
                "At least one investigation step is required"
            )

    @staticmethod
    def _normalize_list(
        values: list[str],
        *,
        uppercase: bool = False,
    ) -> list[str]:
        """Strip and deduplicate text values."""

        normalized_values: list[str] = []

        for value in values:
            if not isinstance(value, str):
                continue

            normalized = value.strip()

            if uppercase:
                normalized = normalized.upper()

            if (
                normalized
                and normalized not in normalized_values
            ):
                normalized_values.append(normalized)

        return normalized_values

    def to_dict(self) -> dict[str, Any]:
        """Return a serializable draft dictionary."""

        return asdict(self)


@dataclass(slots=True)
class CopilotValidationResult:
    """Result of validating an AI-generated draft."""

    valid: bool
    errors: list[str] = field(
        default_factory=list
    )
    warnings: list[str] = field(
        default_factory=list
    )

    def to_dict(self) -> dict[str, Any]:
        """Return a serializable validation result."""

        return asdict(self)
