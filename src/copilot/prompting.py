"""Build evidence-locked prompts for the AI SOC Copilot."""

from __future__ import annotations

import json
from typing import Any

from src.copilot.models import CopilotPrompt
from src.triage.models import AnalystTriagePacket


SYSTEM_RULES = """
You are an AI assistant supporting a human SOC analyst.

Use only the facts contained in the provided triage packet.

Mandatory rules:
1. Do not invent events, users, IP addresses, hosts, times,
   malware, vulnerabilities, commands, or attacker intent.
2. Do not change the supplied risk score, severity, priority,
   confidence, or MITRE ATT&CK mappings.
3. Every factual security observation must be grounded in one
   or more supplied event IDs.
4. Clearly identify uncertainty and alternative explanations.
5. Investigation steps may recommend validation, but must not
   claim that recommended checks have already been completed.
6. Containment actions are recommendations for analyst review.
   Do not state that any action has been executed.
7. Return valid JSON only. Do not include Markdown.
""".strip()


OUTPUT_SCHEMA = {
    "executive_summary": "string",
    "assessment": "string",
    "key_observations": [
        "string"
    ],
    "investigation_steps": [
        "string"
    ],
    "containment_considerations": [
        "string"
    ],
    "cited_event_ids": [
        "event ID from the supplied packet"
    ],
    "cited_mitre_techniques": [
        "technique ID from the supplied packet"
    ],
    "uncertainties": [
        "string"
    ],
}


def _packet_to_dict(
    packet: AnalystTriagePacket | dict[str, Any],
) -> dict[str, Any]:
    """Convert a supported packet into a dictionary."""

    if isinstance(packet, AnalystTriagePacket):
        return packet.to_dict()

    if isinstance(packet, dict):
        return dict(packet)

    raise TypeError(
        "Copilot prompting requires an "
        "AnalystTriagePacket or dictionary"
    )


def _required_text(
    packet: dict[str, Any],
    field_name: str,
) -> str:
    """Return a required text field."""

    value = packet.get(field_name)

    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"{field_name} is required for copilot prompting"
        )

    return value.strip()


def build_copilot_prompt(
    packet: AnalystTriagePacket | dict[str, Any],
) -> CopilotPrompt:
    """Create an auditable prompt from a triage packet."""

    packet_data = _packet_to_dict(packet)

    case_id = _required_text(
        packet_data,
        "case_id",
    )

    serialized_packet = json.dumps(
        packet_data,
        indent=2,
        sort_keys=True,
    )

    serialized_schema = json.dumps(
        OUTPUT_SCHEMA,
        indent=2,
        sort_keys=True,
    )

    prompt_text = f"""
{SYSTEM_RULES}

TASK:
Review the evidence-backed SOC triage packet and draft an
analyst-facing assessment.

REQUIRED OUTPUT JSON SCHEMA:
{serialized_schema}

TRIAGE PACKET:
{serialized_packet}
""".strip()

    return CopilotPrompt(
        case_id=case_id,
        text=prompt_text,
    )
