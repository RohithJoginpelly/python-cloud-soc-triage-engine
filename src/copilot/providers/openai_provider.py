"""OpenAI Responses API provider for the SOC Copilot."""

from __future__ import annotations

import os
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from src.copilot.models import (
    CopilotDraft,
    CopilotPrompt,
)
from src.copilot.providers.base import ProviderDraft
from src.triage.models import AnalystTriagePacket


class OpenAIDraftSchema(BaseModel):
    """Strict structured-output schema for the model."""

    model_config = ConfigDict(extra="forbid")

    executive_summary: str = Field(min_length=1)
    assessment: str = Field(min_length=1)

    key_observations: list[str] = Field(
        min_length=1
    )

    investigation_steps: list[str] = Field(
        min_length=1
    )

    containment_considerations: list[str]

    cited_event_ids: list[str] = Field(
        min_length=1
    )

    cited_mitre_techniques: list[str]
    uncertainties: list[str]


class OpenAICopilotProvider:
    """Generate structured drafts with the OpenAI API."""

    name = "openai"

    def __init__(
        self,
        *,
        model: str | None = None,
        api_key: str | None = None,
        client: Any | None = None,
    ) -> None:
        resolved_model = (
            model
            or os.getenv("OPENAI_MODEL")
            or "gpt-5.6"
        )

        self.model = resolved_model.strip()

        if not self.model:
            raise ValueError(
                "OpenAI model name is required"
            )

        # Tests can inject a fake client without an API key.
        if client is not None:
            self._client = client
            return

        resolved_api_key = (
            api_key
            or os.getenv("OPENAI_API_KEY")
        )

        if (
            not isinstance(resolved_api_key, str)
            or not resolved_api_key.strip()
        ):
            raise RuntimeError(
                "OPENAI_API_KEY is required when the "
                "OpenAI provider is selected"
            )

        try:
            from openai import OpenAI
        except ImportError as error:
            raise RuntimeError(
                "The OpenAI SDK is not installed. Run "
                "'python -m pip install openai'."
            ) from error

        self._client = OpenAI(
            api_key=resolved_api_key.strip()
        )

    def generate(
        self,
        prompt: CopilotPrompt,
        packet: AnalystTriagePacket | dict[str, Any],
    ) -> ProviderDraft:
        """Generate one structured Copilot draft."""

        # The complete packet is already included in the
        # evidence-locked prompt.
        del packet

        response = self._client.responses.parse(
            model=self.model,
            input=prompt.text,
            text_format=OpenAIDraftSchema,
            store=False,
        )

        parsed = response.output_parsed

        if parsed is None:
            raise RuntimeError(
                "OpenAI returned no parsed Copilot draft"
            )

        draft = CopilotDraft(
            **parsed.model_dump()
        )

        request_id = getattr(
            response,
            "_request_id",
            None,
        )

        return ProviderDraft(
            provider=self.name,
            model=self.model,
            draft=draft,
            request_id=request_id,
        )
