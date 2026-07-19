"""SSH authentication correlation rules."""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from src.correlation_engine.models import (
    CorrelationFinding,
)
from src.normalization.schema import NormalizedEvent


RULE_ID = "CORR-AUTH-001"

RULE_TITLE = (
    "Multiple SSH failures followed by successful login"
)


def _event_to_dictionary(
    event: NormalizedEvent | dict[str, Any],
) -> dict[str, Any]:
    """Convert supported event types into dictionaries."""

    if isinstance(event, NormalizedEvent):
        return event.to_dict()

    if isinstance(event, dict):
        return dict(event)

    raise TypeError(
        "Correlation events must be NormalizedEvent "
        "objects or dictionaries"
    )


def _parse_timestamp(value: Any) -> datetime:
    """Parse normalized ISO-style timestamps as UTC datetimes."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            "Correlation event timestamp is required"
        )

    timestamp = value.strip()

    if timestamp.endswith("Z"):
        timestamp = timestamp[:-1] + "+00:00"

    # Convert offsets such as +0000 into +00:00.
    if re.search(r"[+-]\d{4}$", timestamp):
        timestamp = (
            timestamp[:-5]
            + timestamp[-5:-2]
            + ":"
            + timestamp[-2:]
        )

    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError as error:
        raise ValueError(
            f"Invalid correlation timestamp: {value}"
        ) from error

    if parsed.tzinfo is None:
        parsed = parsed.replace(
            tzinfo=timezone.utc
        )

    return parsed.astimezone(timezone.utc)


def _is_ssh_authentication_event(
    event: dict[str, Any],
) -> bool:
    """Return True for normalized Wazuh SSH authentication events."""

    return (
        event.get("source_product") == "wazuh"
        and event.get("category") == "authentication"
        and event.get("action") == "ssh_authentication"
        and event.get("outcome")
        in {
            "failure",
            "success",
        }
    )


def _grouping_key(
    event: dict[str, Any],
) -> tuple[str, str, str] | None:
    """Build the identity used to associate SSH events."""

    source_ip = event.get("source_ip")
    username = event.get("username")
    destination_host = event.get(
        "destination_host"
    )

    if not all(
        isinstance(value, str) and value.strip()
        for value in (
            source_ip,
            username,
            destination_host,
        )
    ):
        return None

    return (
        source_ip.strip(),
        username.strip(),
        destination_host.strip(),
    )


def detect_ssh_failure_then_success(
    events: Iterable[
        NormalizedEvent | dict[str, Any]
    ],
    *,
    minimum_failures: int = 3,
    window_minutes: int = 15,
) -> list[CorrelationFinding]:
    """Detect repeated SSH failures followed by a success.

    Events must have the same source IP, username, and destination host.
    """

    if minimum_failures < 1:
        raise ValueError(
            "minimum_failures must be at least 1"
        )

    if window_minutes < 1:
        raise ValueError(
            "window_minutes must be at least 1"
        )

    groups: dict[
        tuple[str, str, str],
        list[tuple[datetime, dict[str, Any]]],
    ] = defaultdict(list)

    for original_event in events:
        event = _event_to_dictionary(
            original_event
        )

        if not _is_ssh_authentication_event(
            event
        ):
            continue

        key = _grouping_key(event)

        if key is None:
            continue

        event_time = _parse_timestamp(
            event.get("timestamp")
        )

        groups[key].append(
            (
                event_time,
                event,
            )
        )

    findings: list[CorrelationFinding] = []

    for (
        source_ip,
        username,
        destination_host,
    ), grouped_events in groups.items():
        grouped_events.sort(
            key=lambda item: item[0]
        )

        for success_time, success_event in grouped_events:
            if success_event.get("outcome") != "success":
                continue

            window_start = success_time - timedelta(
                minutes=window_minutes
            )

            failures = [
                (
                    event_time,
                    event,
                )
                for event_time, event in grouped_events
                if (
                    event.get("outcome") == "failure"
                    and window_start
                    <= event_time
                    < success_time
                )
            ]

            if len(failures) < minimum_failures:
                continue

            evidence = failures + [
                (
                    success_time,
                    success_event,
                )
            ]

            event_ids = [
                event["event_id"]
                for _, event in evidence
            ]

            source_products = [
                event["source_product"]
                for _, event in evidence
            ]

            first_seen = failures[0][0].isoformat()
            last_seen = success_time.isoformat()

            confidence = min(
                0.70
                + (
                    len(failures)
                    - minimum_failures
                )
                * 0.05,
                0.95,
            )

            finding = CorrelationFinding(
                rule_id=RULE_ID,
                title=RULE_TITLE,
                description=(
                    f"{len(failures)} failed SSH "
                    "authentication attempts were "
                    "followed by a successful login "
                    f"within {window_minutes} minutes."
                ),
                severity="high",
                confidence=confidence,
                category="credential_access",
                first_seen=first_seen,
                last_seen=last_seen,
                event_ids=event_ids,
                source_products=source_products,
                source_ip=source_ip,
                username=username,
                destination_host=destination_host,
                evidence_summary=(
                    f"{len(failures)} failures followed "
                    "by one successful SSH login from "
                    f"{source_ip} targeting "
                    f"{destination_host} as {username}."
                ),
                recommended_action=(
                    "Verify whether the successful login "
                    "was authorized, review the user's "
                    "session activity, inspect the source "
                    "IP, reset credentials if necessary, "
                    "and confirm MFA or stronger SSH "
                    "controls are enforced."
                ),
                tags=[
                    "ssh",
                    "authentication",
                    "credential_access",
                    "possible_account_compromise",
                ],
            )

            findings.append(finding)

    return findings
