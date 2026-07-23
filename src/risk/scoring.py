"""Deterministic and explainable SOC risk scoring."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from src.correlation_engine.models import CorrelationFinding
from src.risk.models import (
    RiskAssessment,
    RiskFactor,
)


SEVERITY_POINTS = {
    "informational": 5,
    "low": 15,
    "medium": 30,
    "high": 45,
    "critical": 60,
}

COMPROMISE_TAGS = {
    "possible_account_compromise",
    "account_compromise",
    "credential_compromise",
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
        "Risk scoring requires a CorrelationFinding "
        "or dictionary"
    )


def _required_text(
    finding: dict[str, Any],
    field_name: str,
) -> str:
    """Read a required nonempty text field."""

    value = finding.get(field_name)

    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"{field_name} is required for risk scoring"
        )

    return value.strip()


def _normalized_text_set(value: Any) -> set[str]:
    """Convert a list of strings into a normalized set."""

    if not isinstance(value, list):
        return set()

    return {
        item.strip().lower()
        for item in value
        if isinstance(item, str) and item.strip()
    }


def _confidence_points(
    confidence: float,
) -> tuple[int, str]:
    """Map finding confidence to score points."""

    if confidence >= 0.95:
        return (
            10,
            "Correlation confidence is at least 95%.",
        )

    if confidence >= 0.85:
        return (
            8,
            "Correlation confidence is at least 85%.",
        )

    if confidence >= 0.70:
        return (
            5,
            "Correlation confidence is at least 70%.",
        )

    return (
        0,
        "Correlation confidence is below 70%.",
    )


def _risk_level(score: int) -> str:
    """Convert a numerical score into a risk level."""

    if score >= 75:
        return "critical"

    if score >= 50:
        return "high"

    if score >= 25:
        return "medium"

    return "low"


def _priority(level: str) -> str:
    """Map risk level to SOC investigation priority."""

    return {
        "critical": "P1",
        "high": "P2",
        "medium": "P3",
        "low": "P4",
    }[level]


def score_correlation_finding(
    finding: CorrelationFinding | dict[str, Any],
) -> RiskAssessment:
    """Calculate an explainable risk score for one finding."""

    finding_data = _finding_to_dict(finding)

    correlation_id = _required_text(
        finding_data,
        "correlation_id",
    )

    severity = _required_text(
        finding_data,
        "severity",
    ).lower()

    if severity not in SEVERITY_POINTS:
        raise ValueError(
            f"Unsupported finding severity: {severity}"
        )

    try:
        confidence = float(
            finding_data.get("confidence", 0)
        )
    except (TypeError, ValueError) as error:
        raise ValueError(
            "Finding confidence must be numeric"
        ) from error

    if not 0 <= confidence <= 1:
        raise ValueError(
            "Finding confidence must be between 0 and 1"
        )

    factors: list[RiskFactor] = []

    severity_score = SEVERITY_POINTS[severity]

    factors.append(
        RiskFactor(
            name="Base severity",
            points=severity_score,
            reason=(
                f"The correlation finding severity is "
                f"{severity}."
            ),
        )
    )

    source_products = _normalized_text_set(
        finding_data.get("source_products")
    )

    if len(source_products) >= 2:
        factors.append(
            RiskFactor(
                name="Cross-source confirmation",
                points=15,
                reason=(
                    "The activity is confirmed by multiple "
                    f"security products: "
                    f"{', '.join(sorted(source_products))}."
                ),
            )
        )

    tags = _normalized_text_set(
        finding_data.get("tags")
    )

    matching_compromise_tags = (
        tags & COMPROMISE_TAGS
    )

    if matching_compromise_tags:
        factors.append(
            RiskFactor(
                name="Possible compromise",
                points=15,
                reason=(
                    "The evidence indicates possible account "
                    "or credential compromise."
                ),
            )
        )

    confidence_score, confidence_reason = (
        _confidence_points(confidence)
    )

    if confidence_score > 0:
        factors.append(
            RiskFactor(
                name="Correlation confidence",
                points=confidence_score,
                reason=confidence_reason,
            )
        )

    event_ids = finding_data.get("event_ids")

    evidence_count = (
        len(event_ids)
        if isinstance(event_ids, list)
        else 0
    )

    if evidence_count >= 5:
        factors.append(
            RiskFactor(
                name="Evidence volume",
                points=5,
                reason=(
                    f"The finding contains {evidence_count} "
                    "supporting security events."
                ),
            )
        )

    elif evidence_count >= 3:
        factors.append(
            RiskFactor(
                name="Evidence volume",
                points=3,
                reason=(
                    f"The finding contains {evidence_count} "
                    "supporting security events."
                ),
            )
        )

    raw_score = sum(
        factor.points
        for factor in factors
    )

    risk_score = min(raw_score, 100)
    level = _risk_level(risk_score)

    return RiskAssessment(
        correlation_id=correlation_id,
        raw_score=raw_score,
        risk_score=risk_score,
        risk_level=level,
        priority=_priority(level),
        factors=factors,
    )


def score_correlation_findings(
    findings: list[
        CorrelationFinding | dict[str, Any]
    ],
) -> list[RiskAssessment]:
    """Score multiple correlation findings."""

    if not isinstance(findings, list):
        raise TypeError(
            "Correlation findings must be provided as a list"
        )

    return [
        score_correlation_finding(finding)
        for finding in findings
    ]
