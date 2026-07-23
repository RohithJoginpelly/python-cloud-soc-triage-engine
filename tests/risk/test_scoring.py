import pytest

from src.risk.scoring import (
    score_correlation_finding,
    score_correlation_findings,
)


def build_finding(
    *,
    severity: str = "critical",
    confidence: float = 0.88,
    source_products=None,
    tags=None,
    event_count: int = 5,
) -> dict:
    return {
        "correlation_id": "corr-test-001",
        "severity": severity,
        "confidence": confidence,
        "source_products": (
            source_products
            if source_products is not None
            else [
                "snort",
                "wazuh",
            ]
        ),
        "tags": (
            tags
            if tags is not None
            else [
                "possible_account_compromise",
            ]
        ),
        "event_ids": [
            f"event-{index}"
            for index in range(event_count)
        ],
    }


def test_critical_cross_source_finding_scores_100():
    assessment = score_correlation_finding(
        build_finding()
    )

    assert assessment.raw_score == 103
    assert assessment.risk_score == 100
    assert assessment.risk_level == "critical"
    assert assessment.priority == "P1"
    assert len(assessment.factors) == 5


def test_high_single_source_finding():
    assessment = score_correlation_finding(
        build_finding(
            severity="high",
            confidence=0.75,
            source_products=["wazuh"],
            tags=[],
            event_count=2,
        )
    )

    assert assessment.raw_score == 50
    assert assessment.risk_score == 50
    assert assessment.risk_level == "high"
    assert assessment.priority == "P2"


def test_medium_finding():
    assessment = score_correlation_finding(
        build_finding(
            severity="medium",
            confidence=0.50,
            source_products=["wazuh"],
            tags=[],
            event_count=1,
        )
    )

    assert assessment.risk_score == 30
    assert assessment.risk_level == "medium"
    assert assessment.priority == "P3"


def test_low_finding():
    assessment = score_correlation_finding(
        build_finding(
            severity="low",
            confidence=0.50,
            source_products=["snort"],
            tags=[],
            event_count=1,
        )
    )

    assert assessment.risk_score == 15
    assert assessment.risk_level == "low"
    assert assessment.priority == "P4"


def test_three_events_add_evidence_points():
    assessment = score_correlation_finding(
        build_finding(
            severity="medium",
            confidence=0.50,
            source_products=["wazuh"],
            tags=[],
            event_count=3,
        )
    )

    assert assessment.raw_score == 33


def test_cross_source_products_are_deduplicated():
    assessment = score_correlation_finding(
        build_finding(
            severity="medium",
            confidence=0.50,
            source_products=[
                "wazuh",
                "WAZUH",
                "snort",
            ],
            tags=[],
            event_count=1,
        )
    )

    assert assessment.raw_score == 45


def test_invalid_confidence_is_rejected():
    with pytest.raises(
        ValueError,
        match="between 0 and 1",
    ):
        score_correlation_finding(
            build_finding(
                confidence=1.5
            )
        )


def test_unknown_severity_is_rejected():
    with pytest.raises(
        ValueError,
        match="Unsupported finding severity",
    ):
        score_correlation_finding(
            build_finding(
                severity="extreme"
            )
        )


def test_missing_correlation_id_is_rejected():
    finding = build_finding()
    del finding["correlation_id"]

    with pytest.raises(
        ValueError,
        match="correlation_id is required",
    ):
        score_correlation_finding(finding)


def test_multiple_findings_are_scored():
    assessments = score_correlation_findings(
        [
            build_finding(),
            build_finding(
                severity="low",
                confidence=0.50,
                source_products=["snort"],
                tags=[],
                event_count=1,
            ),
        ]
    )

    assert len(assessments) == 2
    assert assessments[0].risk_score == 100
    assert assessments[1].risk_score == 15


def test_collection_must_be_a_list():
    with pytest.raises(
        TypeError,
        match="must be provided as a list",
    ):
        score_correlation_findings(
            {}
        )  # type: ignore[arg-type]
