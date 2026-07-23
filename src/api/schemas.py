"""Pydantic request and response models for the SOC API."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)


CaseStatus = Literal[
    "new",
    "triage",
    "investigating",
    "contained",
    "resolved",
    "closed",
    "false_positive",
]

CopilotProviderName = Literal[
    "fallback",
    "openai",
]


class StrictAPIModel(BaseModel):
    """Base model that rejects unexpected request fields."""

    model_config = ConfigDict(
        extra="forbid"
    )


class HealthResponse(StrictAPIModel):
    """Service health information."""

    status: str
    service: str
    version: str


class CaseResponse(StrictAPIModel):
    """One persisted SOC case."""

    case_id: str
    correlation_id: str
    title: str

    priority: str
    risk_score: int
    risk_level: str

    status: CaseStatus
    created_at: str
    updated_at: str

    assigned_to: str | None = None
    packet: dict[str, Any]
    copilot_result: dict[str, Any] | None = None


class AuditEventResponse(StrictAPIModel):
    """One case audit event."""

    audit_id: int
    case_id: str
    event_type: str
    actor: str
    created_at: str
    details: dict[str, Any]


class CaseUpdateRequest(StrictAPIModel):
    """Allowed analyst updates for a case."""

    status: CaseStatus | None = None

    assigned_to: str | None = Field(
        default=None,
        max_length=254,
    )

    note: str | None = Field(
        default=None,
        max_length=4000,
    )

    actor: str = Field(
        default="analyst",
        min_length=1,
        max_length=254,
    )

    @model_validator(mode="after")
    def validate_update(
        self,
    ) -> "CaseUpdateRequest":
        """Require at least one meaningful case change."""

        has_note = (
            isinstance(self.note, str)
            and bool(self.note.strip())
        )

        if (
            self.status is None
            and self.assigned_to is None
            and not has_note
        ):
            raise ValueError(
                "At least one case update is required"
            )

        return self


class SSHPipelineRequest(StrictAPIModel):
    """Request to run the cross-source SSH pipeline."""

    snort_file: str = Field(
        min_length=1,
        max_length=500,
        description=(
            "Snort JSON filename relative to the "
            "configured input directory."
        ),
    )

    wazuh_file: str = Field(
        min_length=1,
        max_length=500,
        description=(
            "Wazuh JSON filename relative to the "
            "configured input directory."
        ),
    )

    provider: CopilotProviderName = "fallback"

    actor: str = Field(
        default="soc-api",
        min_length=1,
        max_length=254,
    )


class PipelineResponse(StrictAPIModel):
    """Summary returned after pipeline execution."""

    snort_event_count: int
    wazuh_event_count: int
    total_event_count: int

    finding_count: int
    saved_case_count: int

    provider: str
    database_path: str
    case_ids: list[str]
