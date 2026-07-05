from rule_loader import get_rule


DEFAULT_BASE_SCORE = {
    "Low": 25,
    "Medium": 50,
    "High": 75,
    "Critical": 95,
}


def add_severity_score(alert: dict) -> dict:
    severity = alert.get("severity", "Low")
    rule = get_rule(alert.get("rule_id"))

    score = rule.get("base_score")

    if score is None:
        score = DEFAULT_BASE_SCORE.get(severity, 25)

    if alert.get("user_role") == "Unknown":
        score += 5

    alert["risk_score"] = min(score, 100)

    return alert
