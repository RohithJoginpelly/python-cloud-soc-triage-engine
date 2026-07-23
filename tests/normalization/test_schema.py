import pytest

from src.normalization.schema import NormalizedEvent


def build_test_event() -> NormalizedEvent:
    return NormalizedEvent(
        timestamp="2026-07-18T15:00:00Z",
        source_type="Cloud",
        source_product="CloudTrail",
        category="Authentication",
        action="ConsoleLogin",
        outcome="Failure",
        severity="High",
        username="admin-user",
        source_ip="192.168.119.131",
        cloud_provider="aws",
        cloud_account_id="123456789012",
        cloud_region="us-east-1",
        tags=["AWS", "Authentication", "aws"],
        raw_event={
            "eventName": "ConsoleLogin",
            "eventTime": "2026-07-18T15:00:00Z",
        },
    )


def test_normalized_event_creation():
    event = build_test_event()

    assert event.event_id.startswith("evt-")
    assert event.source_type == "cloud"
    assert event.source_product == "cloudtrail"
    assert event.category == "authentication"
    assert event.action == "ConsoleLogin"
    assert event.outcome == "failure"
    assert event.severity == "high"


def test_event_id_is_deterministic():
    first_event = build_test_event()
    second_event = build_test_event()

    assert first_event.event_id == second_event.event_id


def test_tags_are_normalized_and_deduplicated():
    event = build_test_event()

    assert event.tags == ["aws", "authentication"]


def test_raw_event_is_preserved():
    event = build_test_event()
    event_dictionary = event.to_dict()

    assert event_dictionary["raw_event"]["eventName"] == "ConsoleLogin"
    assert (
        event_dictionary["raw_event"]["eventTime"]
        == "2026-07-18T15:00:00Z"
    )


def test_invalid_severity_is_rejected():
    with pytest.raises(ValueError, match="Invalid severity"):
        NormalizedEvent(
            timestamp="2026-07-18T15:00:00Z",
            source_type="endpoint",
            source_product="wazuh",
            category="authentication",
            action="ssh_login",
            severity="extreme",
        )


def test_invalid_outcome_is_rejected():
    with pytest.raises(ValueError, match="Invalid outcome"):
        NormalizedEvent(
            timestamp="2026-07-18T15:00:00Z",
            source_type="cloud",
            source_product="cloudtrail",
            category="authentication",
            action="ConsoleLogin",
            outcome="denied",
        )


def test_missing_required_action_is_rejected():
    with pytest.raises(ValueError, match="action is required"):
        NormalizedEvent(
            timestamp="2026-07-18T15:00:00Z",
            source_type="network",
            source_product="snort",
            category="network",
            action="",
        )


def test_raw_event_must_be_dictionary():
    with pytest.raises(TypeError, match="raw_event must be a dictionary"):
        NormalizedEvent(
            timestamp="2026-07-18T15:00:00Z",
            source_type="cloud",
            source_product="cloudtrail",
            category="authentication",
            action="ConsoleLogin",
            raw_event="invalid",  # type: ignore[arg-type]
        )
