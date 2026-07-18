from pathlib import Path

import pytest

from src.normalization.schema import NormalizedEvent
from src.storage.normalized_event_store import (
    load_normalized_events,
    write_normalized_events,
)


def build_event(
    *,
    timestamp: str = "2026-07-18T18:00:00Z",
    source_product: str = "cloudtrail",
    action: str = "ConsoleLogin",
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=timestamp,
        source_type="cloud",
        source_product=source_product,
        category="authentication",
        action=action,
        outcome="failure",
        username="admin",
        source_ip="192.168.119.131",
        raw_event={
            "timestamp": timestamp,
            "action": action,
        },
    )


def test_missing_store_returns_empty_list(
    tmp_path: Path,
):
    events = load_normalized_events(
        tmp_path / "missing.jsonl"
    )

    assert events == []


def test_write_and_load_one_event(
    tmp_path: Path,
):
    store_path = tmp_path / "events.jsonl"
    event = build_event()

    result = write_normalized_events(
        [event],
        store_path,
    )

    stored_events = load_normalized_events(
        store_path
    )

    assert result["inserted"] == 1
    assert result["stored_total"] == 1
    assert len(stored_events) == 1
    assert stored_events[0]["event_id"] == event.event_id


def test_duplicate_event_is_skipped(
    tmp_path: Path,
):
    store_path = tmp_path / "events.jsonl"
    event = build_event()

    write_normalized_events(
        [event],
        store_path,
    )

    result = write_normalized_events(
        [event],
        store_path,
    )

    assert result["inserted"] == 0
    assert result["duplicates_skipped"] == 1
    assert result["stored_total"] == 1


def test_different_events_are_stored(
    tmp_path: Path,
):
    store_path = tmp_path / "events.jsonl"

    first_event = build_event()

    second_event = build_event(
        timestamp="2026-07-18T18:01:00Z",
        source_product="wazuh",
        action="ssh_authentication",
    )

    result = write_normalized_events(
        [first_event, second_event],
        store_path,
    )

    assert result["inserted"] == 2
    assert result["stored_total"] == 2


def test_overwrite_mode_replaces_existing_events(
    tmp_path: Path,
):
    store_path = tmp_path / "events.jsonl"

    first_event = build_event()

    second_event = build_event(
        timestamp="2026-07-18T18:02:00Z",
        action="CreateAccessKey",
    )

    write_normalized_events(
        [first_event],
        store_path,
    )

    result = write_normalized_events(
        [second_event],
        store_path,
        append=False,
    )

    stored_events = load_normalized_events(
        store_path
    )

    assert result["stored_total"] == 1
    assert stored_events[0]["event_id"] == (
        second_event.event_id
    )


def test_dictionary_event_is_supported(
    tmp_path: Path,
):
    store_path = tmp_path / "events.jsonl"
    event = build_event().to_dict()

    result = write_normalized_events(
        [event],
        store_path,
    )

    assert result["inserted"] == 1


def test_event_without_id_is_rejected(
    tmp_path: Path,
):
    store_path = tmp_path / "events.jsonl"

    with pytest.raises(
        ValueError,
        match="must contain an event_id",
    ):
        write_normalized_events(
            [
                {
                    "timestamp": (
                        "2026-07-18T18:00:00Z"
                    )
                }
            ],
            store_path,
        )


def test_invalid_event_type_is_rejected(
    tmp_path: Path,
):
    store_path = tmp_path / "events.jsonl"

    with pytest.raises(
        TypeError,
        match="NormalizedEvent or dictionary",
    ):
        write_normalized_events(
            ["invalid"],
            store_path,
        )


def test_invalid_jsonl_is_rejected(
    tmp_path: Path,
):
    store_path = tmp_path / "invalid.jsonl"

    store_path.write_text(
        "{invalid-json}\n",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="Invalid JSON",
    ):
        load_normalized_events(store_path)


def test_jsonl_entry_requires_event_id(
    tmp_path: Path,
):
    store_path = tmp_path / "missing-id.jsonl"

    store_path.write_text(
        '{"timestamp":"2026-07-18T18:00:00Z"}\n',
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="has no event_id",
    ):
        load_normalized_events(store_path)
