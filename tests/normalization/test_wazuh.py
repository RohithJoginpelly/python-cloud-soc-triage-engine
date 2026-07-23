import pytest

from src.normalization.wazuh import (
    normalize_wazuh_alert,
    normalize_wazuh_alerts,
)


def build_ssh_failure_alert() -> dict:
    return {
        "timestamp": "2026-07-18T16:30:00.000+0000",
        "id": "1752856200.123456",
        "rule": {
            "id": "5712",
            "level": 10,
            "description": "Multiple SSH authentication failures",
            "groups": [
                "syslog",
                "sshd",
                "authentication_failed",
            ],
        },
        "agent": {
            "id": "001",
            "name": "ubuntu-server",
            "ip": "192.168.119.132",
        },
        "data": {
            "srcip": "192.168.119.131",
            "srcport": "51432",
            "srcuser": "admin",
        },
        "location": "/var/log/auth.log",
        "full_log": (
            "Failed password for admin from "
            "192.168.119.131 port 51432 ssh2"
        ),
    }


def test_ssh_failed_authentication_normalization():
    event = normalize_wazuh_alert(
        build_ssh_failure_alert()
    )

    assert event.source_type == "endpoint"
    assert event.source_product == "wazuh"
    assert event.category == "authentication"
    assert event.action == "ssh_authentication"
    assert event.outcome == "failure"
    assert event.severity == "high"
    assert event.username == "admin"
    assert event.source_ip == "192.168.119.131"
    assert event.source_port == 51432
    assert event.destination_ip == "192.168.119.132"
    assert event.destination_host == "ubuntu-server"
    assert event.rule_id == "5712"


@pytest.mark.parametrize(
    ("level", "expected_severity"),
    [
        (3, "informational"),
        (5, "low"),
        (8, "medium"),
        (11, "high"),
        (14, "critical"),
    ],
)
def test_wazuh_level_mapping(
    level,
    expected_severity,
):
    alert = build_ssh_failure_alert()
    alert["rule"]["level"] = level

    event = normalize_wazuh_alert(alert)

    assert event.severity == expected_severity


def test_successful_authentication_outcome():
    alert = build_ssh_failure_alert()
    alert["rule"]["id"] = "5715"
    alert["rule"]["description"] = (
        "SSH authentication successful"
    )
    alert["rule"]["groups"] = [
        "syslog",
        "sshd",
        "authentication_success",
    ]

    event = normalize_wazuh_alert(alert)

    assert event.category == "authentication"
    assert event.outcome == "success"


def test_file_integrity_event():
    alert = {
        "timestamp": "2026-07-18T17:00:00.000+0000",
        "rule": {
            "id": "550",
            "level": 7,
            "description": "Integrity checksum changed",
            "groups": [
                "ossec",
                "syscheck",
                "file_integrity",
            ],
        },
        "agent": {
            "name": "ubuntu-server",
            "ip": "192.168.119.132",
        },
        "syscheck": {
            "event": "modified",
            "path": "/etc/ssh/sshd_config",
        },
    }

    event = normalize_wazuh_alert(alert)

    assert event.category == "file"
    assert event.action == "file_modified"
    assert event.severity == "medium"
    assert event.destination_host == "ubuntu-server"


def test_windows_username_and_ip_are_extracted():
    alert = {
        "timestamp": "2026-07-18T17:10:00.000+0000",
        "rule": {
            "id": "60122",
            "level": 8,
            "description": "Windows logon failure",
            "groups": [
                "windows",
                "authentication_failed",
            ],
        },
        "agent": {
            "name": "windows-endpoint",
            "ip": "192.168.119.130",
        },
        "data": {
            "win": {
                "eventdata": {
                    "targetUserName": "Administrator",
                    "ipAddress": "192.168.119.131",
                }
            }
        },
    }

    event = normalize_wazuh_alert(alert)

    assert event.username == "Administrator"
    assert event.source_ip == "192.168.119.131"
    assert event.destination_host == "windows-endpoint"
    assert event.outcome == "failure"


def test_raw_alert_is_copied():
    raw_alert = build_ssh_failure_alert()
    event = normalize_wazuh_alert(raw_alert)

    raw_alert["rule"]["description"] = "Changed later"

    assert (
        event.raw_event["rule"]["description"]
        == "Multiple SSH authentication failures"
    )


def test_multiple_wazuh_alerts_are_normalized():
    first_alert = build_ssh_failure_alert()
    second_alert = build_ssh_failure_alert()

    second_alert["timestamp"] = (
        "2026-07-18T16:31:00.000+0000"
    )

    events = normalize_wazuh_alerts(
        [first_alert, second_alert]
    )

    assert len(events) == 2
    assert events[0].event_id != events[1].event_id


def test_missing_timestamp_is_rejected():
    alert = build_ssh_failure_alert()
    del alert["timestamp"]

    with pytest.raises(
        ValueError,
        match="Wazuh timestamp is required",
    ):
        normalize_wazuh_alert(alert)


def test_missing_rule_id_is_rejected():
    alert = build_ssh_failure_alert()
    del alert["rule"]["id"]

    with pytest.raises(
        ValueError,
        match="Wazuh rule.id is required",
    ):
        normalize_wazuh_alert(alert)


def test_non_dictionary_alert_is_rejected():
    with pytest.raises(
        TypeError,
        match="Wazuh alert must be a dictionary",
    ):
        normalize_wazuh_alert(
            "invalid"
        )  # type: ignore[arg-type]


def test_alert_collection_must_be_list():
    with pytest.raises(
        TypeError,
        match="Wazuh alerts must be provided as a list",
    ):
        normalize_wazuh_alerts(
            {}
        )  # type: ignore[arg-type]
