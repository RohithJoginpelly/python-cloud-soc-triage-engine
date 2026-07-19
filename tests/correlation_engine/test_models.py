import pytest

from src.correlation_engine.models import (
    CorrelationFinding,
)


def build_finding() -> CorrelationFinding:
    return CorrelationFinding(
        rule_id="CORR-AUTH-001",
        title=(
            "Multiple SSH failures followed by success"
        ),
        description="Possible credential compromise.",
        severity="high",
        confidence=0.8,
        category="credential_access",
        first_seen="2026-07-18T16:20:00+00:00",
        last_seen="2026-07-18T16:28:00+00:00",
        event_ids=[
            "evt-001",
            "evt-002",
            "evt-003",
            "evt-004",
        ],
        source_products=["Wazuh", "wazuh"],
        source_ip="192.168.119.131",
        username="admin",
        destination_host="ubuntu-server",
        tags=["SSH", "ssh", "Credential_Access"],
    )


def test_correlation_finding_creation():
    finding = build_finding()

    assert finding.correlation_id.startswith(
        "corr-"
    )
    assert finding.severity == "high"
    assert finding.source_products == ["wazuh"]
    assert finding.tags == [
        "ssh",
        "credential_access",
    ]


def test_correlation_id_is_deterministic():
    first = build_finding()
    second = build_finding()

    assert (
        first.correlation_id
        == second.correlation_id
    )


def test_invalid_confidence_is_rejected():
    with pytest.raises(
        ValueError,
        match="confidence must be between",
    ):
        CorrelationFinding(
            rule_id="TEST-001",
            title="Test",
            description="Test finding",
            severity="high",
            confidence=1.5,
            category="test",
            first_seen="2026-07-18T16:20:00Z",
            last_seen="2026-07-18T16:21:00Z",
            event_ids=["evt-001"],
        )


def test_empty_event_ids_are_rejected():
    with pytest.raises(
        ValueError,
        match="At least one event_id",
    ):
        CorrelationFinding(
            rule_id="TEST-001",
            title="Test",
            description="Test finding",
            severity="high",
            confidence=0.5,
            category="test",
            first_seen="2026-07-18T16:20:00Z",
            last_seen="2026-07-18T16:21:00Z",
            event_ids=[],
        )
