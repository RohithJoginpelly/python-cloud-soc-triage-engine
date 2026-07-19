"""Deterministic MITRE ATT&CK mapping for SOC findings."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from src.correlation_engine.models import (
    CorrelationFinding,
)
from src.mitre.models import (
    MitreMapping,
    MitreTechnique,
)


TECHNIQUE_CATALOG: dict[
    str,
    dict[str, Any],
] = {
    "T1595": {
        "name": "Active Scanning",
        "tactics": [
            "reconnaissance",
        ],
    },
    "T1110.001": {
        "name": "Password Guessing",
        "tactics": [
            "credential_access",
        ],
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactics": [
            "initial_access",
            "persistence",
            "privilege_escalation",
            "defense_evasion",
        ],
    },
}


RULE_MAPPINGS: dict[
    str,
    list[tuple[str, str]],
] = {
    "CORR-XDR-001": [
        (
            "T1595",
            "Snort detected active SSH reconnaissance "
            "against the target before authentication "
            "activity occurred.",
        ),
        (
            "T1110.001",
            "Wazuh recorded repeated failed SSH "
            "authentication attempts for the same account.",
        ),
        (
            "T1078",
            "A successful SSH login occurred after the "
            "repeated authentication failures.",
        ),
    ],
    "CORR-AUTH-001": [
        (
            "T1110.001",
            "Repeated failed SSH authentication attempts "
            "were recorded for the same account.",
        ),
        (
            "T1078",
            "The failed attempts were followed by a "
            "successful login using the account.",
        ),
    ],
}


TAG_MAPPINGS: dict[str, tuple[str, str]] = {
    "network_reconnaissance": (
        "T1595",
        "The finding contains evidence tagged as "
        "network reconnaissance.",
    ),
    "credential_access": (
        "T1110.001",
        "The finding contains repeated authentication "
        "activity associated with credential access.",
    ),
    "possible_account_compromise": (
        "T1078",
        "The finding indicates possible abuse of a "
        "successfully authenticated account.",
    ),
    "account_compromise": (
        "T1078",
        "The finding indicates possible abuse of a "
        "successfully authenticated account.",
    ),
}


def _finding_to_dict(
    finding: CorrelationFinding | dict[str, Any],
) -> dict[str, Any]:
    """Convert a supported finding into a dictionary."""

    if isinstance(finding, CorrelationFinding):
        return asdict(finding)

    if isinstance(finding, dict):
        return dict(finding)

    raise TypeError(
        "MITRE mapping requires a CorrelationFinding "
        "or dictionary"
    )


def _required_text(
    finding: dict[str, Any],
    field_name: str,
) -> str:
    """Return a required nonempty string field."""

    value = finding.get(field_name)

    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"{field_name} is required for MITRE mapping"
        )

    return value.strip()


def _normalized_tags(value: Any) -> set[str]:
    """Return normalized finding tags."""

    if not isinstance(value, list):
        return set()

    return {
        item.strip().lower()
        for item in value
        if isinstance(item, str) and item.strip()
    }


def _create_technique(
    technique_id: str,
    *,
    confidence: str,
    evidence: str,
) -> MitreTechnique:
    """Create a technique from the trusted catalog."""

    catalog_entry = TECHNIQUE_CATALOG.get(
        technique_id
    )

    if catalog_entry is None:
        raise ValueError(
            "Unknown MITRE ATT&CK technique: "
            f"{technique_id}"
        )

    return MitreTechnique(
        technique_id=technique_id,
        name=catalog_entry["name"],
        tactics=list(
            catalog_entry["tactics"]
        ),
        confidence=confidence,
        evidence=evidence,
    )


def map_finding_to_mitre(
    finding: CorrelationFinding | dict[str, Any],
) -> MitreMapping:
    """Map one correlation finding to ATT&CK techniques."""

    finding_data = _finding_to_dict(finding)

    correlation_id = _required_text(
        finding_data,
        "correlation_id",
    )

    rule_id_value = finding_data.get("rule_id")

    rule_id = (
        rule_id_value.strip().upper()
        if isinstance(rule_id_value, str)
        else ""
    )

    mapped: dict[str, MitreTechnique] = {}

    # Rule mappings are high confidence because the
    # correlation rule guarantees the underlying evidence.
    for technique_id, evidence in RULE_MAPPINGS.get(
        rule_id,
        [],
    ):
        mapped[technique_id] = _create_technique(
            technique_id,
            confidence="high",
            evidence=evidence,
        )

    tags = _normalized_tags(
        finding_data.get("tags")
    )

    # Tag mappings provide a controlled fallback for findings
    # that do not yet have an explicit rule mapping.
    for tag in sorted(tags):
        tag_mapping = TAG_MAPPINGS.get(tag)

        if tag_mapping is None:
            continue

        technique_id, evidence = tag_mapping

        if technique_id in mapped:
            continue

        mapped[technique_id] = _create_technique(
            technique_id,
            confidence="medium",
            evidence=evidence,
        )

    techniques = sorted(
        mapped.values(),
        key=lambda technique: technique.technique_id,
    )

    return MitreMapping(
        correlation_id=correlation_id,
        techniques=techniques,
    )


def map_findings_to_mitre(
    findings: list[
        CorrelationFinding | dict[str, Any]
    ],
) -> list[MitreMapping]:
    """Map multiple correlation findings."""

    if not isinstance(findings, list):
        raise TypeError(
            "Correlation findings must be provided as a list"
        )

    return [
        map_finding_to_mitre(finding)
        for finding in findings
    ]
