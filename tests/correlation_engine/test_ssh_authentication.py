from datetime import datetime, timedelta, timezone

import pytest

from src.correlation_engine.ssh_authentication import (
    detect_ssh_failure_then_success,
)
from src.normalization.schema import NormalizedEvent


BASE_TIME = datetime(
    2026,
    7,
    18,
    16,
    20,
    tzinfo=timezone.utc,
)


def build_event(
    *,
    minute_offset: int,
    outcome: str,
    source_ip: str = "192.168.119.131",
    username: str = "admin",
    destination_host: str = "ubuntu-server",
) -> NormalizedEvent:
    timestamp = (
        BASE_TIME
        + timedelta(minutes=minute_offset)
    ).isoformat()

    return NormalizedEvent(
        timestamp=timestamp,
        source_type="endpoint",
        source_product="wazuh",
        category="authentication",
        action="ssh_authentication",
        outcome=outcome,
        severity="low",
        username=username,
        source_ip=source_ip,
        destination_ip="192.168.119.132",
        destination_host=destination_host,
        raw_event={
            "timestamp": timestamp,
            "outcome": outcome,
            "source_ip": source_ip,
            "username": username,
        },
    )


def build_compromise_sequence():
    return [
        build_event(
            minute_offset=0,
            outcome="failure",
        ),
        build_event(
            minute_offset=2,
            outcome="failure",
        ),
        build_event(
            minute_offset=4,
            outcome="failure",
        ),
        build_event(
            minute_offset=8,
            outcome="success",
        ),
    ]


def test_failure_sequence_followed_by_success():
    findings = detect_ssh_failure_then_success(
        build_compromise_sequence()
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "CORR-AUTH-001"
    assert finding.severity == "high"
    assert finding.source_ip == "192.168.119.131"
    assert finding.username == "admin"
    assert finding.destination_host == (
        "ubuntu-server"
    )
    assert len(finding.event_ids) == 4


def test_fewer_than_minimum_failures_do_not_trigger():
    events = [
        build_event(
            minute_offset=0,
            outcome="failure",
        ),
        build_event(
            minute_offset=2,
            outcome="failure",
        ),
        build_event(
            minute_offset=5,
            outcome="success",
        ),
    ]

    findings = detect_ssh_failure_then_success(
        events
    )

    assert findings == []


def test_different_source_ip_does_not_correlate():
    events = build_compromise_sequence()

    events[-1] = build_event(
        minute_offset=8,
        outcome="success",
        source_ip="203.0.113.10",
    )

    findings = detect_ssh_failure_then_success(
        events
    )

    assert findings == []


def test_different_username_does_not_correlate():
    events = build_compromise_sequence()

    events[-1] = build_event(
        minute_offset=8,
        outcome="success",
        username="different-user",
    )

    findings = detect_ssh_failure_then_success(
        events
    )

    assert findings == []


def test_success_outside_time_window_does_not_trigger():
    events = [
        build_event(
            minute_offset=0,
            outcome="failure",
        ),
        build_event(
            minute_offset=2,
            outcome="failure",
        ),
        build_event(
            minute_offset=4,
            outcome="failure",
        ),
        build_event(
            minute_offset=30,
            outcome="success",
        ),
    ]

    findings = detect_ssh_failure_then_success(
        events,
        window_minutes=15,
    )

    assert findings == []


def test_failure_after_success_is_not_counted():
    events = [
        build_event(
            minute_offset=0,
            outcome="failure",
        ),
        build_event(
            minute_offset=2,
            outcome="failure",
        ),
        build_event(
            minute_offset=4,
            outcome="success",
        ),
        build_event(
            minute_offset=5,
            outcome="failure",
        ),
    ]

    findings = detect_ssh_failure_then_success(
        events
    )

    assert findings == []


def test_dictionary_events_are_supported():
    events = [
        event.to_dict()
        for event in build_compromise_sequence()
    ]

    findings = detect_ssh_failure_then_success(
        events
    )

    assert len(findings) == 1


def test_unrelated_cloudtrail_event_is_ignored():
    events = build_compromise_sequence()

    events.append(
        NormalizedEvent(
            timestamp=BASE_TIME.isoformat(),
            source_type="cloud",
            source_product="cloudtrail",
            category="authentication",
            action="ConsoleLogin",
            outcome="failure",
            raw_event={
                "eventName": "ConsoleLogin",
            },
        )
    )

    findings = detect_ssh_failure_then_success(
        events
    )

    assert len(findings) == 1


def test_minimum_failures_must_be_positive():
    with pytest.raises(
        ValueError,
        match="minimum_failures",
    ):
        detect_ssh_failure_then_success(
            [],
            minimum_failures=0,
        )


def test_window_must_be_positive():
    with pytest.raises(
        ValueError,
        match="window_minutes",
    ):
        detect_ssh_failure_then_success(
            [],
            window_minutes=0,
        )
