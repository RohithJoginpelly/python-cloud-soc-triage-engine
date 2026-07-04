import csv
import ipaddress
from pathlib import Path
from datetime import datetime


KNOWN_IPS_PATH = Path("data/context/known_ips.csv")
USERS_PATH = Path("data/context/users.csv")


def load_csv_by_key(path: Path, key_column: str) -> dict:
    if not path.exists():
        return {}

    with path.open("r", newline="") as file:
        reader = csv.DictReader(file)
        return {row[key_column]: row for row in reader}


def classify_ip_address(ip_value: str) -> str:
    try:
        ip = ipaddress.ip_address(ip_value)

        if ip.is_private:
            return "Private"
        if ip.is_loopback:
            return "Loopback"
        if ip.is_reserved:
            return "Reserved"

        return "Public"

    except ValueError:
        return "Invalid"


def is_business_hours(event_time: str) -> str:
    try:
        clean_time = event_time.replace("Z", "+00:00")
        parsed_time = datetime.fromisoformat(clean_time)

        is_weekday = parsed_time.weekday() < 5
        is_work_hour = 8 <= parsed_time.hour < 18

        if is_weekday and is_work_hour:
            return "Yes"

        return "No"

    except Exception:
        return "Unknown"


def enrich_with_local_context(alert: dict) -> dict:
    known_ips = load_csv_by_key(KNOWN_IPS_PATH, "ip_address")
    users = load_csv_by_key(USERS_PATH, "user_name")

    source_ip = alert.get("source_ip", "")
    user_name = alert.get("user_name", "")
    aws_region = alert.get("aws_region", "")
    event_time = alert.get("event_time", "")

    ip_record = known_ips.get(source_ip, {})
    user_record = users.get(user_name, {})

    alert["ip_type"] = classify_ip_address(source_ip)
    alert["ip_label"] = ip_record.get("label", "Unknown IP")
    alert["ip_reputation"] = ip_record.get("classification", "Unknown")

    alert["business_hours"] = is_business_hours(event_time)

    normal_region = user_record.get("normal_region", "Unknown")
    alert["normal_region"] = normal_region

    if normal_region != "Unknown" and aws_region != normal_region:
        alert["unusual_region"] = "Yes"
    else:
        alert["unusual_region"] = "No"

    admin_user = user_record.get("admin_user", "false").lower() == "true"
    critical_user = user_record.get("critical_user", "false").lower() == "true"

    if critical_user:
        alert["user_risk"] = "Critical user"
    elif admin_user:
        alert["user_risk"] = "Admin user"
    else:
        alert["user_risk"] = "Standard user"

    risk_modifiers = []

    if alert["ip_reputation"] == "Suspicious":
        risk_modifiers.append("Suspicious source IP")

    if alert["business_hours"] == "No":
        risk_modifiers.append("After-hours activity")

    if alert["unusual_region"] == "Yes":
        risk_modifiers.append("Unusual AWS region")

    if critical_user:
        risk_modifiers.append("Critical user account")

    if risk_modifiers:
        alert["local_risk_notes"] = "; ".join(risk_modifiers)
    else:
        alert["local_risk_notes"] = "No additional local risk modifiers"

    base_score = int(alert.get("risk_score", 0))
    modifier_score = 0

    if alert["ip_reputation"] == "Suspicious":
        modifier_score += 5

    if alert["business_hours"] == "No":
        modifier_score += 5

    if alert["unusual_region"] == "Yes":
        modifier_score += 5

    if critical_user:
        modifier_score += 5

    alert["risk_score"] = min(100, base_score + modifier_score)

    return alert
