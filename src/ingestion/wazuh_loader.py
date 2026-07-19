"""File-based Wazuh alert ingestion for SOC Copilot Version 2."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.normalization.schema import NormalizedEvent
from src.normalization.wazuh import normalize_wazuh_alerts


def _extract_alerts(payload: Any) -> list[dict[str, Any]]:
    """Extract Wazuh alerts from supported JSON structures.

    Supported formats:

    1. One alert dictionary
    2. A JSON list of alert dictionaries
    3. {"alerts": [...]}
    4. OpenSearch-style {"hits": {"hits": [{"_source": {...}}]}}
    """

    if isinstance(payload, list):
        alerts = payload

    elif isinstance(payload, dict) and isinstance(
        payload.get("alerts"),
        list,
    ):
        alerts = payload["alerts"]

    elif isinstance(payload, dict) and isinstance(
        payload.get("hits"),
        dict,
    ):
        search_hits = payload["hits"].get("hits", [])

        if not isinstance(search_hits, list):
            raise ValueError(
                "Wazuh hits.hits must be a list"
            )

        alerts = []

        for hit in search_hits:
            if not isinstance(hit, dict):
                raise ValueError(
                    "Every Wazuh search hit must be a dictionary"
                )

            source = hit.get("_source")

            if not isinstance(source, dict):
                raise ValueError(
                    "Every Wazuh search hit must contain "
                    "a dictionary named _source"
                )

            alerts.append(source)

    elif isinstance(payload, dict):
        alerts = [payload]

    else:
        raise ValueError(
            "Unsupported Wazuh JSON structure"
        )

    for index, alert in enumerate(alerts):
        if not isinstance(alert, dict):
            raise ValueError(
                f"Wazuh alert at index {index} "
                "must be a dictionary"
            )

    return alerts


def load_wazuh_alerts(
    file_path: str | Path,
) -> list[dict[str, Any]]:
    """Read raw Wazuh alerts from a JSON file."""

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Wazuh alert file not found: {path}"
        )

    if not path.is_file():
        raise ValueError(
            f"Wazuh alert path is not a file: {path}"
        )

    try:
        payload = json.loads(
            path.read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as error:
        raise ValueError(
            f"Invalid JSON in Wazuh alert file: {path}"
        ) from error

    alerts = _extract_alerts(payload)

    if not alerts:
        raise ValueError(
            "Wazuh alert file contains no alerts"
        )

    return alerts


def ingest_wazuh_file(
    file_path: str | Path,
) -> list[NormalizedEvent]:
    """Load and normalize every Wazuh alert in a JSON file."""

    raw_alerts = load_wazuh_alerts(file_path)

    return normalize_wazuh_alerts(raw_alerts)
