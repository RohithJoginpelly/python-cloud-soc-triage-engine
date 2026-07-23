import json
from pathlib import Path

import pytest

from src.ingestion.wazuh_loader import (
    ingest_wazuh_file,
    load_wazuh_alerts,
)


def build_alert(
    timestamp: str = "2026-07-18T16:30:00.000+0000",
) -> dict:
    return {
        "timestamp": timestamp,
        "rule": {
            "id": "5712",
            "level": 10,
            "description": (
                "Multiple SSH authentication failures"
            ),
            "groups": [
                "sshd",
                "authentication_failed",
            ],
        },
        "agent": {
            "name": "ubuntu-server",
            "ip": "192.168.119.132",
        },
        "data": {
            "srcip": "192.168.119.131",
            "srcuser": "admin",
        },
    }


def write_json(
    path: Path,
    payload,
) -> Path:
    path.write_text(
        json.dumps(payload),
        encoding="utf-8",
    )

    return path


def test_load_single_alert(tmp_path):
    alert_file = write_json(
        tmp_path / "single.json",
        build_alert(),
    )

    alerts = load_wazuh_alerts(alert_file)

    assert len(alerts) == 1
    assert alerts[0]["rule"]["id"] == "5712"


def test_load_alert_list(tmp_path):
    alert_file = write_json(
        tmp_path / "list.json",
        [
            build_alert(),
            build_alert(
                "2026-07-18T16:31:00.000+0000"
            ),
        ],
    )

    alerts = load_wazuh_alerts(alert_file)

    assert len(alerts) == 2


def test_load_alert_wrapper(tmp_path):
    alert_file = write_json(
        tmp_path / "wrapper.json",
        {
            "alerts": [
                build_alert(),
            ]
        },
    )

    alerts = load_wazuh_alerts(alert_file)

    assert len(alerts) == 1


def test_load_opensearch_hits(tmp_path):
    alert_file = write_json(
        tmp_path / "hits.json",
        {
            "hits": {
                "hits": [
                    {
                        "_source": build_alert(),
                    }
                ]
            }
        },
    )

    alerts = load_wazuh_alerts(alert_file)

    assert len(alerts) == 1
    assert alerts[0]["agent"]["name"] == (
        "ubuntu-server"
    )


def test_ingestion_returns_normalized_events(tmp_path):
    alert_file = write_json(
        tmp_path / "ingest.json",
        {
            "alerts": [
                build_alert(),
            ]
        },
    )

    events = ingest_wazuh_file(alert_file)

    assert len(events) == 1
    assert events[0].source_product == "wazuh"
    assert events[0].category == "authentication"
    assert events[0].outcome == "failure"


def test_missing_file_is_rejected(tmp_path):
    missing_file = tmp_path / "missing.json"

    with pytest.raises(
        FileNotFoundError,
        match="Wazuh alert file not found",
    ):
        load_wazuh_alerts(missing_file)


def test_invalid_json_is_rejected(tmp_path):
    invalid_file = tmp_path / "invalid.json"
    invalid_file.write_text(
        "{not-valid-json}",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="Invalid JSON",
    ):
        load_wazuh_alerts(invalid_file)


def test_empty_alert_collection_is_rejected(tmp_path):
    empty_file = write_json(
        tmp_path / "empty.json",
        {
            "alerts": [],
        },
    )

    with pytest.raises(
        ValueError,
        match="contains no alerts",
    ):
        load_wazuh_alerts(empty_file)


def test_non_dictionary_alert_is_rejected(tmp_path):
    invalid_file = write_json(
        tmp_path / "invalid-alert.json",
        {
            "alerts": [
                "not-an-alert",
            ]
        },
    )

    with pytest.raises(
        ValueError,
        match="must be a dictionary",
    ):
        load_wazuh_alerts(invalid_file)


def test_opensearch_hit_requires_source(tmp_path):
    invalid_file = write_json(
        tmp_path / "missing-source.json",
        {
            "hits": {
                "hits": [
                    {
                        "_id": "alert-1",
                    }
                ]
            }
        },
    )

    with pytest.raises(
        ValueError,
        match="must contain a dictionary named _source",
    ):
        load_wazuh_alerts(invalid_file)
