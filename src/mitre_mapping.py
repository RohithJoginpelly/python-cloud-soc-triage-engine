from rule_loader import get_rule


def add_mitre_mapping(alert: dict) -> dict:
    rule = get_rule(alert.get("rule_id"))

    alert["mitre_tactic"] = rule.get("mitre_tactic", "Unknown")
    alert["mitre_technique_id"] = rule.get("mitre_technique_id", "Unknown")
    alert["mitre_technique_name"] = rule.get("mitre_technique_name", "Unknown")

    return alert
