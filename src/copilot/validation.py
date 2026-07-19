"""Validate AI SOC Copilot drafts against supplied evidence."""

from __future__ import annotations

from typing import Any

from src.copilot.models import (
    CopilotDraft,
    CopilotValidationResult,
)
from src.triage.models import AnalystTriagePacket


def _packet_to_dict(
    packet: AnalystTriagePacket | dict[str, Any],
) -> dict[str, Any]:
    """Convert a triage packet into a dictionary."""

    if isinstance(packet, AnalystTriagePacket):
        return packet.to_dict()

    if isinstance(packet, dict):
        return dict(packet)

    raise TypeError(
        "Copilot validation requires an "
        "AnalystTriagePacket or dictionary"
    )


def _draft_to_object(
    draft: CopilotDraft | dict[str, Any],
) -> CopilotDraft:
    """Convert dictionary output into a CopilotDraft."""

    if isinstance(draft, CopilotDraft):
        return draft

    if isinstance(draft, dict):
        try:
            return CopilotDraft(**draft)
        except TypeError as error:
            raise ValueError(
                "Copilot draft does not match the "
                "required output structure"
            ) from error

    raise TypeError(
        "Copilot draft must be a CopilotDraft "
        "or dictionary"
    )


def _string_set(value: Any) -> set[str]:
    """Convert a list into a normalized text set."""

    if not isinstance(value, list):
        return set()

    return {
        item.strip()
        for item in value
        if isinstance(item, str) and item.strip()
    }


def _allowed_mitre_ids(
    packet: dict[str, Any],
) -> set[str]:
    """Extract trusted MITRE technique IDs."""

    techniques = packet.get("mitre_techniques")

    if not isinstance(techniques, list):
        return set()

    allowed_ids: set[str] = set()

    for technique in techniques:
        if not isinstance(technique, dict):
            continue

        technique_id = technique.get(
            "technique_id"
        )

        if (
            isinstance(technique_id, str)
            and technique_id.strip()
        ):
            allowed_ids.add(
                technique_id.strip().upper()
            )

    return allowed_ids


def validate_copilot_draft(
    packet: AnalystTriagePacket | dict[str, Any],
    draft: CopilotDraft | dict[str, Any],
) -> CopilotValidationResult:
    """Validate a model draft against packet evidence."""

    packet_data = _packet_to_dict(packet)
    draft_object = _draft_to_object(draft)

    errors: list[str] = []
    warnings: list[str] = []

    allowed_event_ids = _string_set(
        packet_data.get("event_ids")
    )

    cited_event_ids = set(
        draft_object.cited_event_ids
    )

    invented_event_ids = (
        cited_event_ids - allowed_event_ids
    )

    if invented_event_ids:
        errors.append(
            "Draft cited event IDs that are not present "
            "in the triage packet: "
            + ", ".join(
                sorted(invented_event_ids)
            )
        )

    if not cited_event_ids:
        errors.append(
            "Draft must cite at least one supporting event ID"
        )

    allowed_techniques = _allowed_mitre_ids(
        packet_data
    )

    cited_techniques = {
        technique.upper()
        for technique
        in draft_object.cited_mitre_techniques
    }

    invented_techniques = (
        cited_techniques - allowed_techniques
    )

    if invented_techniques:
        errors.append(
            "Draft cited MITRE techniques that are not "
            "present in the triage packet: "
            + ", ".join(
                sorted(invented_techniques)
            )
        )

    if (
        allowed_techniques
        and not cited_techniques
    ):
        warnings.append(
            "The packet contains MITRE mappings, but the "
            "draft did not cite any techniques"
        )

    missing_event_citations = (
        allowed_event_ids - cited_event_ids
    )

    if missing_event_citations:
        warnings.append(
            f"The draft cited {len(cited_event_ids)} of "
            f"{len(allowed_event_ids)} available evidence "
            "events"
        )

    absolute_language = {
        "definitely compromised",
        "confirmed attacker",
        "certainly malicious",
        "confirmed breach",
    }

    searchable_text = " ".join(
        [
            draft_object.executive_summary,
            draft_object.assessment,
            *draft_object.key_observations,
        ]
    ).lower()

    matched_absolute_terms = sorted(
        term
        for term in absolute_language
        if term in searchable_text
    )

    if matched_absolute_terms:
        warnings.append(
            "Draft contains potentially overconfident "
            "language: "
            + ", ".join(matched_absolute_terms)
        )

    return CopilotValidationResult(
        valid=not errors,
        errors=errors,
        warnings=warnings,
    )
