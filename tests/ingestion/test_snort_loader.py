import json
from pathlib import Path

import pytest

from src.ingestion.snort_loader import (
    ingest_snort_file,
    load_snort_alerts,
)


def build_alert(
    timestamp: str = "2026-07-18T18:20:01Z",
) -> dict:
    return {
        "timestamp": timestamp,
        "src_ip": "192.168.119.131",
        "src_port": 44218,
        "dest_ip": "192.168.119.132",
        "dest_port": 22,
        "proto": "TCP",
        "alert": {
            "gid": 1,
            "sid": 1000001,
            "rev": 1,
            "signature": "Possible SSH SYN scan",
            "priority": 2,
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

    alerts = load_snort_alerts(alert_file)

    assert len(alerts) == 1
    assert alerts[0]["src_ip"] == (
        "192.168.119.131"
    )


def test_load_direct_alert_list(tmp_path):
    alert_file = write_json(
        tmp_path / "list.json",
        [
            build_alert(),
            build_alert(
                "2026-07-18T18:21:01Z"
            ),
        ],
    )

    alerts = load_snort_alerts(alert_file)

    assert len(alerts) == 2


def test_load_alerts_wrapper(tmp_path):
    alert_file = write_json(
        tmp_path / "alerts-wrapper.json",
        {
            "alerts": [
                build_alert(),
            ]
        },
    )

    alerts = load_snort_alerts(alert_file)

    assert len(alerts) == 1


def test_load_events_wrapper(tmp_path):
    alert_file = write_json(
        tmp_path / "events-wrapper.json",
        {
            "events": [
                build_alert(),
            ]
        },
    )

    alerts = load_snort_alerts(alert_file)

    assert len(alerts) == 1


def test_load_search_hits(tmp_path):
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

    alerts = load_snort_alerts(alert_file)

    assert len(alerts) == 1
    assert alerts[0]["dest_port"] == 22


def test_ingestion_returns_normalized_events(
    tmp_path,
):
    alert_file = write_json(
        tmp_path / "ingest.json",
        {
            "alerts": [
                build_alert(),
            ]
        },
    )

    events = ingest_snort_file(alert_file)

    assert len(events) == 1
    assert events[0].source_product == "snort"
    assert events[0].action == "network_scan"
    assert events[0].network_protocol == "tcp"


def test_missing_file_is_rejected(tmp_path):
    missing_file = tmp_path / "missing.json"

    with pytest.raises(
        FileNotFoundError,
        match="Snort alert file not found",
    ):
        load_snort_alerts(missing_file)


def test_invalid_json_is_rejected(tmp_path):
    invalid_file = tmp_path / "invalid.json"

    invalid_file.write_text(
        "{invalid-json}",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="Invalid JSON",
    ):
        load_snort_alerts(invalid_file)


def test_empty_collection_is_rejected(tmp_path):
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
        load_snort_alerts(empty_file)


def test_non_dictionary_alert_is_rejected(
    tmp_path,
):
    invalid_file = write_json(
        tmp_path / "invalid-alert.json",
        {
            "alerts": [
                "invalid",
            ]
        },
    )

    with pytest.raises(
        ValueError,
        match="must be a dictionary",
    ):
        load_snort_alerts(invalid_file)


def test_search_hit_requires_source(tmp_path):
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
        load_snort_alerts(invalid_file)
