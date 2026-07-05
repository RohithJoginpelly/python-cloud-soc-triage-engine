from collections import defaultdict


def detect_failed_logins_followed_by_success(events: list[dict]) -> list[dict]:
    alerts = []
    login_events = []

    for event in events:
        if event["event_name"] == "ConsoleLogin":
            result = event["raw_event"].get("responseElements", {}).get("ConsoleLogin")

            login_events.append({
                **event,
                "login_result": result
            })

    grouped_events = defaultdict(list)

    for event in login_events:
        key = (event["user_name"], event["source_ip"])
        grouped_events[key].append(event)

    for (user_name, source_ip), user_events in grouped_events.items():
        user_events.sort(key=lambda x: x["event_time"])

        failed_count = 0

        for event in user_events:
            if event["login_result"] == "Failure":
                failed_count += 1

            if event["login_result"] == "Success" and failed_count >= 3:
                alerts.append({
                    "rule_id": "AWS-AUTH-001",
                    "title": "Multiple failed logins followed by success",
                    "severity": "High",
                    "description": "Three or more failed console logins were followed by a successful login.",
                    "user_name": user_name,
                    "source_ip": source_ip,
                    "event_time": event["event_time"],
                    "aws_region": event["aws_region"],
                    "evidence": f"{failed_count} failed logins followed by success"
                })

    return alerts


def detect_access_key_created(events: list[dict]) -> list[dict]:
    alerts = []

    for event in events:
        if event["event_name"] == "CreateAccessKey":
            alerts.append({
                "rule_id": "AWS-IAM-001",
                "title": "New IAM access key created",
                "severity": "Medium",
                "description": "A new long-term IAM access key was created.",
                "user_name": event["user_name"],
                "source_ip": event["source_ip"],
                "event_time": event["event_time"],
                "aws_region": event["aws_region"],
                "evidence": "CreateAccessKey event detected"
            })

    return alerts


def detect_privilege_escalation(events: list[dict]) -> list[dict]:
    risky_events = {
        "AttachUserPolicy",
        "AttachRolePolicy",
        "PutUserPolicy",
        "PutRolePolicy",
        "AddUserToGroup",
        "CreatePolicyVersion",
        "SetDefaultPolicyVersion"
    }

    alerts = []

    for event in events:
        if event["event_name"] in risky_events:
            alerts.append({
                "rule_id": "AWS-IAM-002",
                "title": "Possible IAM privilege escalation",
                "severity": "High",
                "description": f"Risky IAM permission change detected: {event['event_name']}",
                "user_name": event["user_name"],
                "source_ip": event["source_ip"],
                "event_time": event["event_time"],
                "aws_region": event["aws_region"],
                "evidence": event["event_name"]
            })

    return alerts


def detect_cloudtrail_tampering(events: list[dict]) -> list[dict]:
    risky_events = {
        "StopLogging",
        "DeleteTrail",
        "UpdateTrail",
        "PutEventSelectors"
    }

    alerts = []

    for event in events:
        if event["event_name"] in risky_events:
            alerts.append({
                "rule_id": "AWS-LOG-001",
                "title": "CloudTrail logging modified or disabled",
                "severity": "Critical",
                "description": f"CloudTrail logging change detected: {event['event_name']}",
                "user_name": event["user_name"],
                "source_ip": event["source_ip"],
                "event_time": event["event_time"],
                "aws_region": event["aws_region"],
                "evidence": event["event_name"]
            })

    return alerts


def detect_root_account_usage(events: list[dict]) -> list[dict]:
    alerts = []

    for event in events:
        raw_event = event["raw_event"]
        user_identity = raw_event.get("userIdentity", {})
        login_result = (raw_event.get("responseElements") or {}).get("ConsoleLogin")

        if user_identity.get("type") == "Root" and event["event_name"] == "ConsoleLogin" and login_result == "Success":
            alerts.append({
                "rule_id": "AWS-ROOT-001",
                "title": "Root account console login detected",
                "severity": "Critical",
                "description": "The AWS root account was used to log in successfully.",
                "user_name": "root-account",
                "source_ip": event["source_ip"],
                "event_time": event["event_time"],
                "aws_region": event["aws_region"],
                "evidence": "Root ConsoleLogin Success"
            })

    return alerts


def detect_public_s3_exposure(events: list[dict]) -> list[dict]:
    risky_events = {
        "PutBucketAcl",
        "PutBucketPolicy",
        "DeletePublicAccessBlock"
    }

    alerts = []

    for event in events:
        if event["event_source"] == "s3.amazonaws.com" and event["event_name"] in risky_events:
            request_parameters = event["raw_event"].get("requestParameters", {})
            bucket_name = request_parameters.get("bucketName", "Unknown bucket")

            alerts.append({
                "rule_id": "AWS-S3-001",
                "title": "Possible public S3 bucket exposure",
                "severity": "High",
                "description": f"S3 public access-related change detected for bucket: {bucket_name}",
                "user_name": event["user_name"],
                "source_ip": event["source_ip"],
                "event_time": event["event_time"],
                "aws_region": event["aws_region"],
                "evidence": event["event_name"]
            })

    return alerts


def detect_security_group_open_to_internet(events: list[dict]) -> list[dict]:
    alerts = []

    for event in events:
        if event["event_source"] == "ec2.amazonaws.com" and event["event_name"] == "AuthorizeSecurityGroupIngress":
            request_parameters = event["raw_event"].get("requestParameters", {})
            ip_permissions = request_parameters.get("ipPermissions", [])

            for permission in ip_permissions:
                from_port = permission.get("fromPort")
                to_port = permission.get("toPort")
                ip_ranges = permission.get("ipRanges", [])

                for ip_range in ip_ranges:
                    cidr_ip = ip_range.get("cidrIp")

                    if cidr_ip == "0.0.0.0/0":
                        alerts.append({
                            "rule_id": "AWS-NET-001",
                            "title": "Security group opened to the internet",
                            "severity": "High",
                            "description": f"Security group ingress allows internet access on port {from_port}-{to_port}.",
                            "user_name": event["user_name"],
                            "source_ip": event["source_ip"],
                            "event_time": event["event_time"],
                            "aws_region": event["aws_region"],
                            "evidence": f"0.0.0.0/0 allowed on port {from_port}-{to_port}"
                        })

    return alerts


def run_all_detections(events: list[dict]) -> list[dict]:
    alerts = []

    alerts.extend(detect_failed_logins_followed_by_success(events))
    alerts.extend(detect_access_key_created(events))
    alerts.extend(detect_privilege_escalation(events))
    alerts.extend(detect_cloudtrail_tampering(events))
    alerts.extend(detect_root_account_usage(events))
    alerts.extend(detect_public_s3_exposure(events))
    alerts.extend(detect_security_group_open_to_internet(events))

    return alerts
