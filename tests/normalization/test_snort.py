import pytest

from src.normalization.snort import (
    normalize_snort_alert,
    normalize_snort_alerts,
)


def build_scan_alert() -> dict:
    """Return a reusable Snort SSH scan alert."""

    return {
        "timestamp": "2026-07-18T18:20:01+00:00",
        "event_type": "alert",
        "src_ip": "192.168.119.131",
        "src_port": 44218,
        "dest_ip": "192.168.119.132",
        "dest_port": 22,
        "proto": "TCP",
        "alert": {
            "gid": 1,
            "sid": 1000001,
            "rev": 1,
            "signature": "LOCAL Possible SSH SYN scan",
            "category": "Attempted Information Leak",
            "priority": 2,
        },
    }


def test_snort_scan_normalization():
    event = normalize_snort_alert(
        build_scan_alert()
    )

    assert event.source_type == "network"
    assert event.source_product == "snort"
    assert event.category == "network_intrusion"
    assert event.action == "network_scan"
    assert event.outcome == "unknown"
    assert event.severity == "high"

    assert event.source_ip == "192.168.119.131"
    assert event.source_port == 44218
    assert event.destination_ip == "192.168.119.132"
    assert event.destination_port == 22
    assert event.network_protocol == "tcp"

    assert event.rule_id == "1:1000001:1"
    assert event.rule_name == (
        "LOCAL Possible SSH SYN scan"
    )


@pytest.mark.parametrize(
    ("priority", "expected_severity"),
    [
        (1, "critical"),
        (2, "high"),
        (3, "medium"),
        (4, "low"),
        (None, "informational"),
    ],
)
def test_snort_priority_mapping(
    priority,
    expected_severity,
):
    alert = build_scan_alert()
    alert["alert"]["priority"] = priority

    event = normalize_snort_alert(alert)

    assert event.severity == expected_severity


@pytest.mark.parametrize(
    ("signature", "expected_action"),
    [
        (
            "LOCAL Possible Nmap port scan",
            "network_scan",
        ),
        (
            "Possible SSH brute force attack",
            "credential_attack",
        ),
        (
            "Possible remote code execution exploit",
            "exploit_attempt",
        ),
        (
            "Possible malware command and control",
            "malicious_network_traffic",
        ),
        (
            "Unknown custom network detection",
            "network_intrusion_alert",
        ),
    ],
)
def test_signature_action_mapping(
    signature,
    expected_action,
):
    alert = build_scan_alert()
    alert["alert"]["signature"] = signature

    event = normalize_snort_alert(alert)

    assert event.action == expected_action


def test_top_level_rule_fields_are_supported():
    alert = {
        "timestamp": "2026-07-18T18:30:00Z",
        "src_ip": "203.0.113.20",
        "dest_ip": "192.168.119.132",
        "dest_port": 443,
        "proto": "TCP",
        "gid": 1,
        "sid": 2000001,
        "rev": 2,
        "msg": "Possible web exploit attempt",
        "priority": 1,
    }

    event = normalize_snort_alert(alert)

    assert event.action == "exploit_attempt"
    assert event.rule_id == "1:2000001:2"
    assert event.severity == "critical"
    assert event.network_protocol == "tcp"


def test_raw_alert_is_copied():
    raw_alert = build_scan_alert()
    event = normalize_snort_alert(raw_alert)

    raw_alert["alert"]["signature"] = "Changed later"

    assert (
        event.raw_event["alert"]["signature"]
        == "LOCAL Possible SSH SYN scan"
    )


def test_multiple_snort_alerts_are_normalized():
    first_alert = build_scan_alert()
    second_alert = build_scan_alert()

    second_alert["timestamp"] = (
        "2026-07-18T18:21:01+00:00"
    )

    events = normalize_snort_alerts(
        [first_alert, second_alert]
    )

    assert len(events) == 2
    assert events[0].event_id != events[1].event_id


def test_missing_timestamp_is_rejected():
    alert = build_scan_alert()
    del alert["timestamp"]

    with pytest.raises(
        ValueError,
        match="Snort alert timestamp is required",
    ):
        normalize_snort_alert(alert)


def test_missing_signature_is_rejected():
    alert = build_scan_alert()
    del alert["alert"]["signature"]

    with pytest.raises(
        ValueError,
        match="Snort alert signature is required",
    ):
        normalize_snort_alert(alert)


def test_invalid_alert_type_is_rejected():
    with pytest.raises(
        TypeError,
        match="Snort alert must be a dictionary",
    ):
        normalize_snort_alert(
            "invalid"
        )  # type: ignore[arg-type]


def test_alert_collection_must_be_list():
    with pytest.raises(
        TypeError,
        match="Snort alerts must be provided as a list",
    ):
        normalize_snort_alerts(
            {}
        )  # type: ignore[arg-type]
