MITRE_MAPPINGS = {
    "AWS-AUTH-001": {
        "mitre_tactic": "Credential Access",
        "mitre_technique_id": "T1110",
        "mitre_technique_name": "Brute Force"
    },
    "AWS-IAM-001": {
        "mitre_tactic": "Persistence",
        "mitre_technique_id": "T1098",
        "mitre_technique_name": "Account Manipulation"
    },
    "AWS-IAM-002": {
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique_id": "T1098",
        "mitre_technique_name": "Account Manipulation"
    },
    "AWS-LOG-001": {
        "mitre_tactic": "Defense Evasion",
        "mitre_technique_id": "T1562.008",
        "mitre_technique_name": "Disable or Modify Cloud Logs"
    },
    "AWS-ROOT-001": {
        "mitre_tactic": "Initial Access",
        "mitre_technique_id": "T1078",
        "mitre_technique_name": "Valid Accounts"
    },
    "AWS-S3-001": {
        "mitre_tactic": "Collection",
        "mitre_technique_id": "T1530",
        "mitre_technique_name": "Data from Cloud Storage"
    },
    "AWS-NET-001": {
        "mitre_tactic": "Defense Evasion",
        "mitre_technique_id": "T1578",
        "mitre_technique_name": "Modify Cloud Compute Infrastructure"
    }
}


def add_mitre_mapping(alert: dict) -> dict:
    mapping = MITRE_MAPPINGS.get(alert.get("rule_id"), {})

    alert["mitre_tactic"] = mapping.get("mitre_tactic", "Unknown")
    alert["mitre_technique_id"] = mapping.get("mitre_technique_id", "Unknown")
    alert["mitre_technique_name"] = mapping.get("mitre_technique_name", "Unknown")

    return alert
