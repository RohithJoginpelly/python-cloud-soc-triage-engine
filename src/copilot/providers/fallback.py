"""Deterministic no-AI fallback for SOC Copilot drafts."""

from __future__ import annotations

from typing import Any

from src.copilot.models import (
    CopilotDraft,
    CopilotPrompt,
)
from src.copilot.providers.base import ProviderDraft
from src.triage.models import AnalystTriagePacket


def _packet_to_dict(
    packet: AnalystTriagePacket | dict[str, Any],
) -> dict[str, Any]:
    """Convert a supported triage packet to a dictionary."""

    if isinstance(packet, AnalystTriagePacket):
        return packet.to_dict()

    if isinstance(packet, dict):
        return dict(packet)

    raise TypeError(
        "Fallback provider requires an "
        "AnalystTriagePacket or dictionary"
    )


def _required_text(
    packet: dict[str, Any],
    field_name: str,
) -> str:
    """Return one required nonempty text field."""

    value = packet.get(field_name)

    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"{field_name} is required by fallback provider"
        )

    return value.strip()


def _string_list(value: Any) -> list[str]:
    """Extract valid strings from a list."""

    if not isinstance(value, list):
        return []

    return [
        item.strip()
        for item in value
        if isinstance(item, str) and item.strip()
    ]


def _mitre_ids(packet: dict[str, Any]) -> list[str]:
    """Extract trusted MITRE technique IDs."""

    techniques = packet.get("mitre_techniques")

    if not isinstance(techniques, list):
        return []

    technique_ids: list[str] = []

    for technique in techniques:
        if not isinstance(technique, dict):
            continue

        technique_id = technique.get("technique_id")

        if (
            isinstance(technique_id, str)
            and technique_id.strip()
        ):
            normalized = technique_id.strip().upper()

            if normalized not in technique_ids:
                technique_ids.append(normalized)

    return technique_ids


class FallbackCopilotProvider:
    """Generate an evidence-grounded draft without an LLM."""

    name = "fallback"
    model = "deterministic-v1"

    def generate(
        self,
        prompt: CopilotPrompt,
        packet: AnalystTriagePacket | dict[str, Any],
    ) -> ProviderDraft:
        """Build a deterministic analyst draft."""

        packet_data = _packet_to_dict(packet)

        title = _required_text(
            packet_data,
            "title",
        )

        summary = _required_text(
            packet_data,
            "summary",
        )

        priority = _required_text(
            packet_data,
            "priority",
        ).upper()

        risk_level = _required_text(
            packet_data,
            "risk_level",
        ).lower()

        recommended_action = _required_text(
            packet_data,
            "recommended_action",
        )

        event_ids = _string_list(
            packet_data.get("event_ids")
        )

        if not event_ids:
            raise ValueError(
                "Fallback provider requires evidence event IDs"
            )

        source_products = _string_list(
            packet_data.get("source_products")
        )

        risk_score = packet_data.get("risk_score")

        if not isinstance(risk_score, int):
            raise ValueError(
                "risk_score must be an integer"
            )

        observations = [
            summary,
            (
                f"The deterministic engine assigned "
                f"{priority} priority with a risk score "
                f"of {risk_score}/100."
            ),
        ]

        if source_products:
            observations.append(
                "The finding is supported by: "
                + ", ".join(source_products)
                + "."
            )

        source_ip = packet_data.get("source_ip")
        username = packet_data.get("username")
        destination_host = packet_data.get(
            "destination_host"
        )

        if isinstance(source_ip, str) and source_ip.strip():
            observations.append(
                f"Observed source IP: {source_ip.strip()}."
            )

        if isinstance(username, str) and username.strip():
            observations.append(
                f"Associated username: {username.strip()}."
            )

        if (
            isinstance(destination_host, str)
            and destination_host.strip()
        ):
            observations.append(
                "Affected destination host: "
                f"{destination_host.strip()}."
            )

        draft = CopilotDraft(
            executive_summary=(
                f"{priority} {risk_level} finding: {title}."
            ),
            assessment=(
                f"{summary} The activity requires human "
                "analyst validation before it is classified "
                "as authorized or malicious."
            ),
            key_observations=observations,
            investigation_steps=[
                (
                    "Validate whether the identified user or "
                    "system owner authorized the activity."
                ),
                (
                    "Review the supporting events in "
                    "chronological order."
                ),
                (
                    "Inspect authentication, process, and "
                    "network activity associated with the case."
                ),
            ],
            containment_considerations=[
                (
                    "Consider restricting the source only "
                    "after analyst review confirms the action "
                    "is appropriate."
                ),
                (
                    "Consider credential rotation if account "
                    "misuse is confirmed."
                ),
            ],
            cited_event_ids=event_ids,
            cited_mitre_techniques=_mitre_ids(
                packet_data
            ),
            uncertainties=[
                (
                    "The available telemetry does not by "
                    "itself prove whether the activity was "
                    "authorized."
                )
            ],
        )

        return ProviderDraft(
            provider=self.name,
            model=self.model,
            draft=draft,
            request_id=None,
        )
