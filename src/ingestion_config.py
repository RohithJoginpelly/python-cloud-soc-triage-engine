import json
import os
from datetime import datetime, timezone


DEFAULT_CONFIG = {
    "mode": "sample",
    "input_file": "data/raw/sample_cloudtrail.json",
    "source_name": "local_sample_cloudtrail",
    "environment": "lab",
    "cloud_provider": "aws",
}


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def load_ingestion_config(config_path="config/ingestion_config.json"):
    config = DEFAULT_CONFIG.copy()

    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as file:
            loaded_config = json.load(file)

        config.update(loaded_config)

    config["mode"] = os.getenv("SOC_SOURCE_MODE", config["mode"])
    config["input_file"] = os.getenv("SOC_INPUT_FILE", config["input_file"])
    config["source_name"] = os.getenv("SOC_SOURCE_NAME", config["source_name"])
    config["environment"] = os.getenv("SOC_ENVIRONMENT", config["environment"])
    config["cloud_provider"] = os.getenv("SOC_CLOUD_PROVIDER", config["cloud_provider"])

    return config


def add_ingestion_metadata(alert, config, ingested_at):
    alert["source_mode"] = config.get("mode", "unknown")
    alert["source_name"] = config.get("source_name", "unknown")
    alert["environment"] = config.get("environment", "unknown")
    alert["cloud_provider"] = config.get("cloud_provider", "unknown")
    alert["input_file"] = config.get("input_file", "unknown")
    alert["ingested_at"] = ingested_at

    return alert


def write_ingestion_status(
    config,
    input_file,
    processed_events,
    rule_alerts,
    correlation_alerts,
    total_alerts,
    ingested_at,
    output_file="data/ingestion/ingestion_status.json",
):
    status = {
        "mode": config.get("mode", "unknown"),
        "source_name": config.get("source_name", "unknown"),
        "environment": config.get("environment", "unknown"),
        "cloud_provider": config.get("cloud_provider", "unknown"),
        "input_file": input_file,
        "processed_events": processed_events,
        "rule_alerts": rule_alerts,
        "correlation_alerts": correlation_alerts,
        "total_alerts": total_alerts,
        "ingested_at": ingested_at,
    }

    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(status, file, indent=2)

    return status
