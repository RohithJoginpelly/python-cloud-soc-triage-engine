from datetime import datetime, timedelta


def parse_event_time(event_time: str):
    try:
        clean_time = event_time.replace("Z", "+00:00")
        return datetime.fromisoformat(clean_time)
    except Exception:
        return None


def event_contains_login_result(event: dict, result: str) -> bool:
    raw_event_text = str(event.get("raw_event", {}))
    return event.get("event_name") == "ConsoleLogin" and result in raw_event_text


def detect_cloud_compromise_chain(events: list[dict]) -> list[dict]:
    alerts = []

    sorted_events = sorted(
        events,
        key=lambda event: event.get("event_time", "")
    )

    failed_logins = [
        event for event in sorted_events
        if event_contains_login_result(event, "Failure")
    ]

    successful_logins = [
        event for event in sorted_events
        if event_contains_login_result(event, "Success")
    ]

    access_key_events = [
        event for event in sorted_events
        if event.get("event_name") == "CreateAccessKey"
    ]

    privilege_events = [
        event for event in sorted_events
        if event.get("event_name") in [
            "AttachUserPolicy",
            "AttachRolePolicy",
            "PutUserPolicy",
            "PutRolePolicy"
        ]
    ]

    logging_events = [
        event for event in sorted_events
        if event.get("event_name") in [
            "StopLogging",
            "DeleteTrail",
            "UpdateTrail"
        ]
    ]

    for success_event in successful_logins:
        success_time = parse_event_time(success_event.get("event_time", ""))

        if not success_time:
            continue

        window_end = success_time + timedelta(hours=2)

        related_failures = []
        for failure_event in failed_logins:
            failure_time = parse_event_time(failure_event.get("event_time", ""))
            if failure_time and success_time - timedelta(minutes=30) <= failure_time <= success_time:
                related_failures.append(failure_event)

        access_key_event = None
        for event in access_key_events:
            event_time = parse_event_time(event.get("event_time", ""))
            if event_time and success_time <= event_time <= window_end:
                access_key_event = event
                break

        privilege_event = None
        for event in privilege_events:
            event_time = parse_event_time(event.get("event_time", ""))
            if event_time and success_time <= event_time <= window_end:
                privilege_event = event
                break

        logging_event = None
        for event in logging_events:
            event_time = parse_event_time(event.get("event_time", ""))
            if event_time and success_time <= event_time <= window_end:
                logging_event = event
                break

        if access_key_event and privilege_event and logging_event:
            evidence_parts = []

            if related_failures:
                evidence_parts.append(f"{len(related_failures)} failed console login attempt(s) before success")

            evidence_parts.extend([
                f"successful console login by {success_event.get('user_name', 'Unknown')}",
                f"access key created by {access_key_event.get('user_name', 'Unknown')}",
                f"IAM privilege change by {privilege_event.get('user_name', 'Unknown')}",
                f"CloudTrail logging modified by {logging_event.get('user_name', 'Unknown')}"
            ])

            alerts.append({
                "rule_id": "AWS-CORR-001",
                "title": "Possible cloud account compromise chain",
                "severity": "Critical",
                "user_name": privilege_event.get("user_name", "Unknown"),
                "source_ip": privilege_event.get("source_ip", success_event.get("source_ip", "Unknown")),
                "aws_region": privilege_event.get("aws_region", "Unknown"),
                "event_time": logging_event.get("event_time", ""),
                "description": (
                    "Multiple suspicious cloud events occurred in sequence within a short time window. "
                    "This may indicate account compromise, attacker persistence, privilege escalation, "
                    "and defense evasion."
                ),
                "evidence": " -> ".join(evidence_parts),
                "recommended_action": (
                    "Immediately investigate the affected user session, disable suspicious access keys, "
                    "review and revert unauthorized IAM permission changes, re-enable and validate CloudTrail logging, "
                    "rotate credentials, verify MFA, and check for additional unauthorized activity."
                )
            })

            break

    return alerts


def run_correlation_detections(events: list[dict]) -> list[dict]:
    alerts = []
    alerts.extend(detect_cloud_compromise_chain(events))
    return alerts
