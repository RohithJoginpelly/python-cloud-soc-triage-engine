"""Snort network-alert normalizer for AI SOC Copilot Version 2."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from src.normalization.schema import NormalizedEvent


def _as_dictionary(value: Any) -> dict[str, Any]:
    """Return a dictionary or an empty dictionary."""

    return value if isinstance(value, dict) else {}


def _first_value(
    mapping: dict[str, Any],
    *keys: str,
) -> Any:
    """Return the first nonempty value found in the supplied keys."""

    for key in keys:
        value = mapping.get(key)

        if value is not None and value != "":
            return value

    return None


def _to_integer(value: Any) -> int | None:
    """Safely convert ports, priorities, and rule numbers to integers."""

    if value is None or value == "":
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _map_priority_to_severity(priority: Any) -> str:
    """Convert Snort priority into the normalized severity format."""

    numeric_priority = _to_integer(priority)

    if numeric_priority is None:
        return "informational"

    if numeric_priority <= 1:
        return "critical"

    if numeric_priority == 2:
        return "high"

    if numeric_priority == 3:
        return "medium"

    return "low"


def _build_rule_id(
    alert_data: dict[str, Any],
) -> str | None:
    """Build a Snort rule identifier using GID, SID, and revision."""

    gid = _to_integer(
        _first_value(
            alert_data,
            "gid",
            "generator_id",
        )
    )

    sid = _to_integer(
        _first_value(
            alert_data,
            "sid",
            "signature_id",
        )
    )

    revision = _to_integer(
        _first_value(
            alert_data,
            "rev",
            "revision",
        )
    )

    if sid is None:
        return None

    if gid is not None and revision is not None:
        return f"{gid}:{sid}:{revision}"

    if gid is not None:
        return f"{gid}:{sid}"

    return str(sid)


def _infer_action(signature: str) -> str:
    """Infer a stable action name from the Snort signature."""

    search_text = signature.lower()

    if any(
        term in search_text
        for term in (
            "port scan",
            "portscan",
            "syn scan",
            "nmap",
        )
    ):
        return "network_scan"

    if any(
        term in search_text
        for term in (
            "brute force",
            "password attack",
            "credential attack",
        )
    ):
        return "credential_attack"

    if any(
        term in search_text
        for term in (
            "exploit",
            "remote code execution",
            "buffer overflow",
        )
    ):
        return "exploit_attempt"

    if any(
        term in search_text
        for term in (
            "malware",
            "trojan",
            "ransomware",
            "command and control",
        )
    ):
        return "malicious_network_traffic"

    return "network_intrusion_alert"


def normalize_snort_alert(
    raw_alert: dict[str, Any],
) -> NormalizedEvent:
    """Convert one Snort alert into a NormalizedEvent."""

    if not isinstance(raw_alert, dict):
        raise TypeError(
            "Snort alert must be a dictionary"
        )

    timestamp = _first_value(
        raw_alert,
        "timestamp",
        "event_time",
        "time",
    )

    if not isinstance(timestamp, str) or not timestamp.strip():
        raise ValueError(
            "Snort alert timestamp is required"
        )

    alert_data = _as_dictionary(
        raw_alert.get("alert")
    )

    # Some Snort exports store rule information at the top level.
    if not alert_data:
        alert_data = raw_alert

    signature = _first_value(
        alert_data,
        "signature",
        "msg",
        "message",
        "description",
    )

    if not isinstance(signature, str) or not signature.strip():
        raise ValueError(
            "Snort alert signature is required"
        )

    signature = signature.strip()

    source_ip = _first_value(
        raw_alert,
        "src_ip",
        "source_ip",
        "src",
    )

    destination_ip = _first_value(
        raw_alert,
        "dest_ip",
        "destination_ip",
        "dst_ip",
        "dst",
    )

    protocol = _first_value(
        raw_alert,
        "proto",
        "protocol",
        "network_protocol",
    )

    classification = _first_value(
        alert_data,
        "category",
        "classification",
        "class",
    )

    tags = [
        "snort",
        "network",
        "network_intrusion",
    ]

    if isinstance(protocol, str) and protocol.strip():
        tags.append(protocol)

    if (
        isinstance(classification, str)
        and classification.strip()
    ):
        tags.append(classification)

    return NormalizedEvent(
        timestamp=timestamp,
        source_type="network",
        source_product="snort",
        category="network_intrusion",
        action=_infer_action(signature),
        outcome="unknown",
        severity=_map_priority_to_severity(
            _first_value(
                alert_data,
                "priority",
                "severity",
            )
        ),
        source_ip=(
            str(source_ip).strip()
            if source_ip is not None
            else None
        ),
        source_port=_to_integer(
            _first_value(
                raw_alert,
                "src_port",
                "source_port",
                "sport",
            )
        ),
        destination_ip=(
            str(destination_ip).strip()
            if destination_ip is not None
            else None
        ),
        destination_port=_to_integer(
            _first_value(
                raw_alert,
                "dest_port",
                "destination_port",
                "dst_port",
                "dport",
            )
        ),
        network_protocol=(
            str(protocol).strip()
            if protocol is not None
            else None
        ),
        rule_id=_build_rule_id(alert_data),
        rule_name=signature,
        message=signature,
        tags=tags,
        raw_event=deepcopy(raw_alert),
    )


def normalize_snort_alerts(
    alerts: list[dict[str, Any]],
) -> list[NormalizedEvent]:
    """Normalize multiple Snort alerts."""

    if not isinstance(alerts, list):
        raise TypeError(
            "Snort alerts must be provided as a list"
        )

    return [
        normalize_snort_alert(alert)
        for alert in alerts
    ]
