"""Common contracts for AI Copilot model providers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Protocol

from src.copilot.models import (
    CopilotDraft,
    CopilotPrompt,
)
from src.triage.models import AnalystTriagePacket


@dataclass(slots=True)
class ProviderDraft:
    """Draft and metadata returned by a provider."""

    provider: str
    model: str
    draft: CopilotDraft
    request_id: str | None = None

    def __post_init__(self) -> None:
        self.provider = self.provider.strip().lower()
        self.model = self.model.strip()

        if not self.provider:
            raise ValueError(
                "Provider name is required"
            )

        if not self.model:
            raise ValueError(
                "Provider model is required"
            )

        if isinstance(self.request_id, str):
            self.request_id = (
                self.request_id.strip() or None
            )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary."""

        return asdict(self)


class CopilotProvider(Protocol):
    """Interface implemented by all model providers."""

    name: str
    model: str

    def generate(
        self,
        prompt: CopilotPrompt,
        packet: AnalystTriagePacket | dict[str, Any],
    ) -> ProviderDraft:
        """Generate one structured Copilot draft."""
