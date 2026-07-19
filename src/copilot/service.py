"""Run the SOC Copilot through a validated provider."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from typing import Any

from src.copilot.models import (
    CopilotDraft,
    CopilotValidationResult,
)
from src.copilot.prompting import build_copilot_prompt
from src.copilot.providers.base import (
    CopilotProvider,
)
from src.copilot.providers.fallback import (
    FallbackCopilotProvider,
)
from src.copilot.providers.openai_provider import (
    OpenAICopilotProvider,
)
from src.copilot.validation import (
    validate_copilot_draft,
)
from src.triage.models import AnalystTriagePacket


class CopilotValidationError(ValueError):
    """Raised when provider output fails evidence validation."""


@dataclass(slots=True)
class CopilotRunResult:
    """Auditable result of one Copilot execution."""

    case_id: str
    prompt_id: str
    provider: str
    model: str
    draft: CopilotDraft
    validation: CopilotValidationResult
    request_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary."""

        return asdict(self)


def create_copilot_provider(
    provider_name: str | None = None,
) -> CopilotProvider:
    """Create a provider from configuration."""

    resolved_name = (
        provider_name
        or os.getenv("COPILOT_PROVIDER")
        or "fallback"
    )

    normalized_name = (
        resolved_name.strip().lower()
    )

    if normalized_name == "fallback":
        return FallbackCopilotProvider()

    if normalized_name == "openai":
        return OpenAICopilotProvider()

    raise ValueError(
        f"Unsupported Copilot provider: "
        f"{normalized_name}"
    )


def run_copilot(
    packet: AnalystTriagePacket | dict[str, Any],
    *,
    provider: CopilotProvider | None = None,
    provider_name: str | None = None,
) -> CopilotRunResult:
    """Generate and validate one Copilot draft."""

    prompt = build_copilot_prompt(packet)

    selected_provider = (
        provider
        if provider is not None
        else create_copilot_provider(
            provider_name
        )
    )

    provider_result = selected_provider.generate(
        prompt,
        packet,
    )

    validation = validate_copilot_draft(
        packet,
        provider_result.draft,
    )

    if not validation.valid:
        error_text = "; ".join(
            validation.errors
        )

        raise CopilotValidationError(
            "Copilot provider output failed "
            f"evidence validation: {error_text}"
        )

    return CopilotRunResult(
        case_id=prompt.case_id,
        prompt_id=prompt.prompt_id,
        provider=provider_result.provider,
        model=provider_result.model,
        draft=provider_result.draft,
        validation=validation,
        request_id=provider_result.request_id,
    )
