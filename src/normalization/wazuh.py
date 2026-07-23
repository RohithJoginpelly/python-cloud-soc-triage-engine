"""Wazuh alert normalizer for AI SOC Copilot Version 2."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from src.normalization.schema import NormalizedEvent


def _as_dictionary(value: Any) -> dict[str, Any]:
    """Return a dictionary or an empty dictionary for invalid input."""

    return value if isinstance(value, dict) else {}


def _to_integer(value: Any) -> int | None:
    """Safely convert values such as port numbers to integers."""

    if value is None or value == "":
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _normalize_groups(rule: dict[str, Any]) -> list[str]:
    """Return Wazuh rule groups as a clean list of strings."""

    groups = rule.get("groups", [])

    if isinstance(groups, str):
        groups = groups.split(",")

    if not isinstance(groups, list):
        return []

    return [
        group.strip().lower()
        for group in groups
        if isinstance(group, str) and group.strip()
    ]


def _map_wazuh_level_to_severity(level: Any) -> str:
    """Convert Wazuh's numeric rule level into common severity labels.

    Wazuh levels normally range from 0 through 15.
    """

    numeric_level = _to_integer(level)

    if numeric_level is None:
        return "informational"

    if numeric_level <= 3:
        return "informational"

    if numeric_level <= 6:
        return "low"

    if numeric_level <= 9:
        return "medium"

    if numeric_level <= 12:
        return "high"

    return "critical"


def _build_search_text(
    rule: dict[str, Any],
    data: dict[str, Any],
    location: str | None,
) -> str:
    """Combine useful Wazuh fields for category and outcome inference."""

    groups = _normalize_groups(rule)
    description = str(rule.get("description", ""))
    status = str(data.get("status", ""))
    action = str(data.get("action", ""))
    location_text = location or ""

    return " ".join(
        groups
        + [
            description,
            status,
            action,
            location_text,
        ]
    ).lower()


def _infer_category(
    rule: dict[str, Any],
    data: dict[str, Any],
    location: str | None,
) -> str:
    """Infer a vendor-neutral event category."""

    search_text = _build_search_text(rule, data, location)

    if any(
        term in search_text
        for term in (
            "authentication",
            "authentication_failed",
            "authentication_success",
            "sshd",
            "login",
            "logon",
            "pam",
        )
    ):
        return "authentication"

    if any(
        term in search_text
        for term in (
            "syscheck",
            "file_integrity",
            "file changed",
            "file added",
            "file deleted",
            "checksum changed",
        )
    ):
        return "file"

    if any(
        term in search_text
        for term in (
            "firewall",
            "network",
            "ids",
            "suricata",
            "snort",
            "port scan",
        )
    ):
        return "network"

    if any(
        term in search_text
        for term in (
            "malware",
            "rootkit",
            "trojan",
            "virus",
            "ransomware",
        )
    ):
        return "malware"

    if any(
        term in search_text
        for term in (
            "vulnerability",
            "vulnerability-detector",
            "cve-",
        )
    ):
        return "vulnerability"

    if any(
        term in search_text
        for term in (
            "web",
            "apache",
            "nginx",
            "http",
        )
    ):
        return "web"

    return "endpoint_activity"


def _infer_outcome(
    rule: dict[str, Any],
    data: dict[str, Any],
    location: str | None,
) -> str:
    """Infer whether the observed action succeeded or failed."""

    search_text = _build_search_text(rule, data, location)

    failure_terms = (
        "failed",
        "failure",
        "denied",
        "invalid",
        "unauthorized",
        "incorrect password",
        "authentication_failed",
    )

    success_terms = (
        "successful",
        "success",
        "accepted password",
        "authentication_success",
        "logged in",
    )

    if any(term in search_text for term in failure_terms):
        return "failure"

    if any(term in search_text for term in success_terms):
        return "success"

    return "unknown"


def _infer_action(
    category: str,
    rule: dict[str, Any],
    data: dict[str, Any],
    alert: dict[str, Any],
) -> str:
    """Create a stable action name for the normalized event."""

    explicit_action = data.get("action")

    if isinstance(explicit_action, str) and explicit_action.strip():
        return explicit_action.strip()

    groups = _normalize_groups(rule)
    search_text = " ".join(
        groups
        + [
            str(rule.get("description", "")),
            str(alert.get("location", "")),
        ]
    ).lower()

    if category == "authentication":
        if "ssh" in search_text or "sshd" in search_text:
            return "ssh_authentication"

        return "authentication"

    if category == "file":
        syscheck = _as_dictionary(alert.get("syscheck"))
        file_event = syscheck.get("event")

        if isinstance(file_event, str) and file_event.strip():
            return f"file_{file_event.strip().lower()}"

        return "file_integrity_change"

    if category == "network":
        return "network_alert"

    if category == "malware":
        return "malware_detection"

    if category == "vulnerability":
        return "vulnerability_detected"

    if category == "web":
        return "web_activity"

    return "wazuh_alert"


def _extract_windows_event_data(
    data: dict[str, Any],
) -> dict[str, Any]:
    """Return nested Windows event data when present."""

    windows_data = _as_dictionary(data.get("win"))

    return _as_dictionary(windows_data.get("eventdata"))


def _extract_username(data: dict[str, Any]) -> str | None:
    """Extract a username from Linux, network, or Windows alerts."""

    windows_event_data = _extract_windows_event_data(data)

    candidates = (
        data.get("srcuser"),
        data.get("dstuser"),
        data.get("user"),
        data.get("username"),
        windows_event_data.get("targetUserName"),
        windows_event_data.get("subjectUserName"),
        windows_event_data.get("accountName"),
    )

    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()

    return None


def _extract_source_ip(data: dict[str, Any]) -> str | None:
    """Extract the origin IP from common Wazuh fields."""

    windows_event_data = _extract_windows_event_data(data)

    candidates = (
        data.get("srcip"),
        data.get("src_ip"),
        data.get("source_ip"),
        windows_event_data.get("ipAddress"),
        windows_event_data.get("sourceAddress"),
    )

    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            normalized = candidate.strip()

            if normalized not in {"-", "::1"}:
                return normalized

    return None


def normalize_wazuh_alert(alert: dict[str, Any]) -> NormalizedEvent:
    """Convert one Wazuh alert into a NormalizedEvent."""

    if not isinstance(alert, dict):
        raise TypeError("Wazuh alert must be a dictionary")

    timestamp = alert.get("timestamp")

    if not isinstance(timestamp, str) or not timestamp.strip():
        raise ValueError("Wazuh timestamp is required")

    rule = _as_dictionary(alert.get("rule"))
    rule_id = rule.get("id")

    if rule_id is None or not str(rule_id).strip():
        raise ValueError("Wazuh rule.id is required")

    data = _as_dictionary(alert.get("data"))
    agent = _as_dictionary(alert.get("agent"))
    predecoder = _as_dictionary(alert.get("predecoder"))

    location = alert.get("location")

    if not isinstance(location, str):
        location = None

    category = _infer_category(rule, data, location)
    action = _infer_action(category, rule, data, alert)
    description = rule.get("description")

    if not isinstance(description, str) or not description.strip():
        description = f"Wazuh rule {rule_id}"

    destination_ip = data.get("dstip")

    if not isinstance(destination_ip, str) or not destination_ip.strip():
        destination_ip = agent.get("ip")

    destination_host = agent.get("name")

    if not isinstance(destination_host, str) or not destination_host.strip():
        destination_host = predecoder.get("hostname")

    groups = _normalize_groups(rule)

    return NormalizedEvent(
        timestamp=timestamp,
        source_type="endpoint",
        source_product="wazuh",
        category=category,
        action=action,
        outcome=_infer_outcome(rule, data, location),
        severity=_map_wazuh_level_to_severity(rule.get("level")),

        username=_extract_username(data),

        source_ip=_extract_source_ip(data),
        source_port=_to_integer(
            data.get("srcport")
            or data.get("src_port")
        ),

        destination_ip=destination_ip,
        destination_port=_to_integer(
            data.get("dstport")
            or data.get("dst_port")
        ),
        destination_host=destination_host,

        rule_id=str(rule_id),
        rule_name=description,
        message=description,

        tags=[
            "wazuh",
            "endpoint",
            category,
            *groups,
        ],

        raw_event=deepcopy(alert),
    )


def normalize_wazuh_alerts(
    alerts: list[dict[str, Any]],
) -> list[NormalizedEvent]:
    """Normalize multiple Wazuh alerts."""

    if not isinstance(alerts, list):
        raise TypeError("Wazuh alerts must be provided as a list")

    return [
        normalize_wazuh_alert(alert)
        for alert in alerts
    ]
