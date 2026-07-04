import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"

if str(SRC_PATH) not in sys.path:
    sys.path.append(str(SRC_PATH))


from parser import load_cloudtrail_file, normalize_event
from detections import run_all_detections
from correlation import run_correlation_detections
from enrichment import enrich_alert
from severity import add_severity_score
from mitre_mapping import add_mitre_mapping
from local_enrichment import enrich_with_local_context
from report_generator import generate_incident_report


SAMPLE_LOG_PATH = "data/raw/sample_cloudtrail.json"


def build_final_alerts():
    raw_events = load_cloudtrail_file(SAMPLE_LOG_PATH)
    normalized_events = [normalize_event(event) for event in raw_events]

    rule_alerts = run_all_detections(normalized_events)
    correlation_alerts = run_correlation_detections(normalized_events)

    alerts = rule_alerts + correlation_alerts

    final_alerts = []
    for alert in alerts:
        alert = enrich_alert(alert)
        alert = add_severity_score(alert)
        alert = add_mitre_mapping(alert)
        alert = enrich_with_local_context(alert)
        alert["status"] = "Open"
        final_alerts.append(alert)

    return normalized_events, rule_alerts, correlation_alerts, final_alerts


def test_parser_loads_sample_cloudtrail_events():
    raw_events = load_cloudtrail_file(SAMPLE_LOG_PATH)

    assert len(raw_events) == 10


def test_normalized_events_have_required_fields():
    raw_events = load_cloudtrail_file(SAMPLE_LOG_PATH)
    normalized = normalize_event(raw_events[0])

    required_fields = [
        "event_time",
        "event_source",
        "event_name",
        "aws_region",
        "source_ip",
        "user_name",
        "raw_event"
    ]

    for field in required_fields:
        assert field in normalized


def test_detection_rules_generate_expected_alert_count():
    normalized_events, rule_alerts, correlation_alerts, final_alerts = build_final_alerts()

    assert len(rule_alerts) == 7


def test_correlation_engine_generates_compromise_chain_alert():
    normalized_events, rule_alerts, correlation_alerts, final_alerts = build_final_alerts()

    rule_ids = [alert["rule_id"] for alert in correlation_alerts]

    assert "AWS-CORR-001" in rule_ids


def test_full_pipeline_generates_eight_total_alerts():
    normalized_events, rule_alerts, correlation_alerts, final_alerts = build_final_alerts()

    assert len(final_alerts) == 8


def test_mitre_mapping_is_added_to_alerts():
    normalized_events, rule_alerts, correlation_alerts, final_alerts = build_final_alerts()

    for alert in final_alerts:
        assert "mitre_tactic" in alert
        assert "mitre_technique_id" in alert
        assert "mitre_technique_name" in alert
        assert alert["mitre_technique_id"] != "Unknown"


def test_local_enrichment_is_added_to_alerts():
    normalized_events, rule_alerts, correlation_alerts, final_alerts = build_final_alerts()

    for alert in final_alerts:
        assert "ip_type" in alert
        assert "ip_reputation" in alert
        assert "user_risk" in alert
        assert "local_risk_notes" in alert


def test_correlation_alert_has_critical_risk_score():
    normalized_events, rule_alerts, correlation_alerts, final_alerts = build_final_alerts()

    correlation_alert = next(
        alert for alert in final_alerts
        if alert["rule_id"] == "AWS-CORR-001"
    )

    assert correlation_alert["severity"] == "Critical"
    assert correlation_alert["risk_score"] == 100


def test_report_generator_creates_markdown_content():
    normalized_events, rule_alerts, correlation_alerts, final_alerts = build_final_alerts()

    incident = final_alerts[0].copy()
    incident["incident_id"] = "INC-TEST"
    incident["created_at"] = "2026-01-01T00:00:00Z"
    incident["updated_at"] = "2026-01-01T00:00:00Z"
    incident["analyst_notes"] = "Test analyst note"

    report = generate_incident_report(incident)

    assert "# Incident Report: INC-TEST" in report
    assert "MITRE ATT&CK Mapping" in report
    assert "Local Enrichment" in report
    assert "Recommended Analyst Action" in report
