KNOWN_USERS = {
    "student-user": {
        "role": "Normal IAM User",
        "department": "Student Lab",
        "normal_region": "us-east-1"
    },
    "admin-user": {
        "role": "Cloud Admin",
        "department": "IT Security",
        "normal_region": "us-east-1"
    },
    "storage-admin": {
        "role": "Storage Administrator",
        "department": "Cloud Infrastructure",
        "normal_region": "us-east-1"
    },
    "network-admin": {
        "role": "Network Administrator",
        "department": "Cloud Infrastructure",
        "normal_region": "us-east-1"
    },
    "root-account": {
        "role": "AWS Root Account",
        "department": "Account Owner",
        "normal_region": "us-east-1"
    }
}


def get_recommended_action(rule_id: str) -> str:
    if rule_id == "AWS-AUTH-001":
        return "Verify with the user, review login history, reset password if unauthorized, and enforce MFA."

    if rule_id == "AWS-IAM-001":
        return "Confirm whether the access key was approved. Disable and rotate the key if suspicious."

    if rule_id == "AWS-IAM-002":
        return "Review IAM permission change, check actor activity, and remove unauthorized privileges."

    if rule_id == "AWS-LOG-001":
        return "Immediately verify CloudTrail status, re-enable logging, and investigate the actor."

    if rule_id == "AWS-ROOT-001":
        return "Verify whether root login was approved, confirm MFA usage, review all account activity after login, and avoid routine root account use."

    if rule_id == "AWS-S3-001":
        return "Review bucket public access settings, inspect bucket policy/ACL changes, restore private access if unauthorized, and confirm business justification."

    if rule_id == "AWS-NET-001":
        return "Review the security group rule, remove 0.0.0.0/0 if not approved, restrict access to trusted IPs, and verify exposed services."

    return "Review the event and escalate if unauthorized."


def enrich_alert(alert: dict) -> dict:
    user_name = alert.get("user_name")

    user_context = KNOWN_USERS.get(user_name, {
        "role": "Unknown",
        "department": "Unknown",
        "normal_region": "Unknown"
    })

    alert["user_role"] = user_context["role"]
    alert["department"] = user_context["department"]
    alert["normal_region"] = user_context["normal_region"]
    alert["recommended_action"] = get_recommended_action(alert["rule_id"])

    return alert
