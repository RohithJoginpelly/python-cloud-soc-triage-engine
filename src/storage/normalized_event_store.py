"""Persistent JSONL storage for normalized security events."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from src.normalization.schema import NormalizedEvent


def _serialize_event(
    event: NormalizedEvent | dict[str, Any],
) -> dict[str, Any]:
    """Convert an event into a validated dictionary."""

    if isinstance(event, NormalizedEvent):
        event_data = event.to_dict()
    elif isinstance(event, dict):
        event_data = dict(event)
    else:
        raise TypeError(
            "Event must be a NormalizedEvent or dictionary"
        )

    event_id = event_data.get("event_id")

    if not isinstance(event_id, str) or not event_id.strip():
        raise ValueError(
            "Every normalized event must contain an event_id"
        )

    return event_data


def load_normalized_events(
    file_path: str | Path,
) -> list[dict[str, Any]]:
    """Load normalized events from a JSONL file."""

    path = Path(file_path)

    if not path.exists():
        return []

    if not path.is_file():
        raise ValueError(
            f"Normalized event path is not a file: {path}"
        )

    events: list[dict[str, Any]] = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            stripped_line = line.strip()

            if not stripped_line:
                continue

            try:
                event = json.loads(stripped_line)
            except json.JSONDecodeError as error:
                raise ValueError(
                    "Invalid JSON in normalized event store "
                    f"at line {line_number}"
                ) from error

            if not isinstance(event, dict):
                raise ValueError(
                    "Normalized event store entry "
                    f"at line {line_number} must be a dictionary"
                )

            event_id = event.get("event_id")

            if not isinstance(event_id, str) or not event_id.strip():
                raise ValueError(
                    "Normalized event store entry "
                    f"at line {line_number} has no event_id"
                )

            events.append(event)

    return events


def _write_jsonl_atomically(
    file_path: Path,
    events: list[dict[str, Any]],
) -> None:
    """Write all events using a temporary file and atomic replacement."""

    file_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_path = file_path.with_suffix(
        file_path.suffix + ".tmp"
    )

    with temporary_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        for event in events:
            json.dump(
                event,
                file,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            )
            file.write("\n")

    temporary_path.replace(file_path)


def write_normalized_events(
    events: Iterable[
        NormalizedEvent | dict[str, Any]
    ],
    file_path: str | Path,
    *,
    append: bool = True,
    deduplicate: bool = True,
) -> dict[str, Any]:
    """Write normalized events and return a storage summary.

    When append is True, existing events remain in the store.

    When deduplicate is True, events with an event_id already present
    in the store are skipped.
    """

    path = Path(file_path)

    existing_events = (
        load_normalized_events(path)
        if append
        else []
    )

    serialized_events = [
        _serialize_event(event)
        for event in events
    ]

    stored_events = list(existing_events)
    existing_ids = {
        event["event_id"]
        for event in stored_events
    }

    inserted = 0
    duplicates_skipped = 0

    for event in serialized_events:
        event_id = event["event_id"]

        if deduplicate and event_id in existing_ids:
            duplicates_skipped += 1
            continue

        stored_events.append(event)
        existing_ids.add(event_id)
        inserted += 1

    _write_jsonl_atomically(
        path,
        stored_events,
    )

    return {
        "file_path": str(path),
        "existing_before": len(existing_events),
        "received": len(serialized_events),
        "inserted": inserted,
        "duplicates_skipped": duplicates_skipped,
        "stored_total": len(stored_events),
    }
