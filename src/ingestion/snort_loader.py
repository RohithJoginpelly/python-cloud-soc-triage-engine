"""File-based Snort alert ingestion."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.normalization.schema import NormalizedEvent
from src.normalization.snort import normalize_snort_alerts


def _extract_snort_alerts(payload: Any) -> list[dict[str, Any]]:
    """Extract alerts from supported Snort JSON structures."""

    if isinstance(payload, list):
        alerts = payload

    elif isinstance(payload, dict) and isinstance(
        payload.get("alerts"), list
    ):
        alerts = payload["alerts"]

    elif isinstance(payload, dict) and isinstance(
        payload.get("events"), list
    ):
        alerts = payload["events"]

    elif isinstance(payload, dict) and isinstance(
        payload.get("hits"), dict
    ):
        search_hits = payload["hits"].get("hits", [])

        if not isinstance(search_hits, list):
            raise ValueError("Snort hits.hits must be a list")

        alerts = []

        for hit in search_hits:
            if not isinstance(hit, dict):
                raise ValueError(
                    "Every Snort search hit must be a dictionary"
                )

            source = hit.get("_source")

            if not isinstance(source, dict):
                raise ValueError(
                    "Every Snort search hit must contain "
                    "a dictionary named _source"
                )

            alerts.append(source)

    elif isinstance(payload, dict):
        alerts = [payload]

    else:
        raise ValueError("Unsupported Snort JSON structure")

    for index, alert in enumerate(alerts):
        if not isinstance(alert, dict):
            raise ValueError(
                f"Snort alert at index {index} must be a dictionary"
            )

    return alerts


def load_snort_alerts(
    file_path: str | Path,
) -> list[dict[str, Any]]:
    """Load raw Snort alerts from a JSON file."""

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Snort alert file not found: {path}"
        )

    if not path.is_file():
        raise ValueError(
            f"Snort alert path is not a file: {path}"
        )

    try:
        payload = json.loads(
            path.read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as error:
        raise ValueError(
            f"Invalid JSON in Snort alert file: {path}"
        ) from error

    alerts = _extract_snort_alerts(payload)

    if not alerts:
        raise ValueError(
            "Snort alert file contains no alerts"
        )

    return alerts


def ingest_snort_file(
    file_path: str | Path,
) -> list[NormalizedEvent]:
    """Load and normalize all Snort alerts in a JSON file."""

    return normalize_snort_alerts(
        load_snort_alerts(file_path)
    )
