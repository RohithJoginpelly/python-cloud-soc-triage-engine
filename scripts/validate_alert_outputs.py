import csv
import json
import sqlite3
from pathlib import Path


ALERTS_CSV = Path("data/alerts/alerts.csv")
INCIDENT_DB = Path("data/incidents/incidents.db")
NOTIFICATION_OUTBOX = Path("data/notifications/notification_outbox.json")
REPORTS_DIR = Path("reports/generated")

EXPECTED_TOTAL_ALERTS = 8
EXPECTED_CORRELATION_RULE = "AWS-CORR-001"


def load_alerts():
    assert ALERTS_CSV.exists(), f"Missing alert CSV: {ALERTS_CSV}"

    with ALERTS_CSV.open(newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def validate_alert_csv(alerts):
    assert len(alerts) == EXPECTED_TOTAL_ALERTS, (
        f"Expected {EXPECTED_TOTAL_ALERTS} alerts, found {len(alerts)}"
    )

    rule_ids = {alert["rule_id"] for alert in alerts}

    assert EXPECTED_CORRELATION_RULE in rule_ids, (
        f"Missing correlation rule: {EXPECTED_CORRELATION_RULE}"
    )

    assert any(alert["severity"] == "Critical" for alert in alerts), (
        "Expected at least one Critical alert"
    )

    assert any(alert["severity"] == "High" for alert in alerts), (
        "Expected at least one High alert"
    )

    assert all(alert.get("analyst_summary") for alert in alerts), (
        "Every alert should include an analyst summary"
    )


def validate_sqlite_incidents():
    assert INCIDENT_DB.exists(), f"Missing incident database: {INCIDENT_DB}"

    conn = sqlite3.connect(INCIDENT_DB)
    conn.row_factory = sqlite3.Row

    total = conn.execute("SELECT COUNT(*) AS count FROM incidents").fetchone()["count"]

    corr = conn.execute(
        "SELECT COUNT(*) AS count FROM incidents WHERE rule_id = ?",
        (EXPECTED_CORRELATION_RULE,),
    ).fetchone()["count"]

    critical = conn.execute(
        "SELECT COUNT(*) AS count FROM incidents WHERE severity = 'Critical'"
    ).fetchone()["count"]

    conn.close()

    assert total == EXPECTED_TOTAL_ALERTS, (
        f"Expected {EXPECTED_TOTAL_ALERTS} incidents in SQLite, found {total}"
    )

    assert corr == 1, "Expected exactly one correlation incident"

    assert critical >= 1, "Expected at least one Critical incident"


def validate_notification_outbox():
    assert NOTIFICATION_OUTBOX.exists(), (
        f"Missing notification outbox: {NOTIFICATION_OUTBOX}"
    )

    with NOTIFICATION_OUTBOX.open("r", encoding="utf-8") as file:
        outbox = json.load(file)

    notifications = outbox.get("notifications", [])

    assert outbox.get("notification_count") == len(notifications), (
        "Notification count does not match notification list length"
    )

    assert len(notifications) == 7, (
        f"Expected 7 High/Critical notifications, found {len(notifications)}"
    )

    priorities = {notification.get("priority") for notification in notifications}
    severities = {notification.get("severity") for notification in notifications}

    assert "P1" in priorities, "Expected P1 notification for Critical alerts"
    assert "P2" in priorities, "Expected P2 notification for High alerts"
    assert "Critical" in severities, "Expected Critical notification"
    assert "High" in severities, "Expected High notification"
    assert "Medium" not in severities, "Medium alerts should not create notifications"


def validate_reports():
    assert REPORTS_DIR.exists(), f"Missing reports directory: {REPORTS_DIR}"

    report_files = list(REPORTS_DIR.glob("INC-*.md"))

    assert len(report_files) >= EXPECTED_TOTAL_ALERTS, (
        f"Expected at least {EXPECTED_TOTAL_ALERTS} incident reports, found {len(report_files)}"
    )


def main():
    alerts = load_alerts()

    validate_alert_csv(alerts)
    validate_sqlite_incidents()
    validate_notification_outbox()
    validate_reports()

    print("Alert output validation passed.")
    print(f"Validated alerts: {len(alerts)}")
    print("Validated correlation rule: AWS-CORR-001")
    print("Validated notification routing: Critical=P1, High=P2, Medium=none")
    print("Validated generated reports.")


if __name__ == "__main__":
    main()
