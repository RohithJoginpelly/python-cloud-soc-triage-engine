"""Readiness logging and metrics integration tests."""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

from fastapi.testclient import TestClient

from src.api.app import create_app


API_KEY = "readiness-observability-key"


def build_app(tmp_path: Path):
    """Create an isolated readiness application."""

    input_root = tmp_path / "telemetry"
    input_root.mkdir()

    app = create_app(
        database_path=tmp_path / "cases.db",
        input_root=input_root,
        api_key=API_KEY,
        session_secret=(
            "readiness-observability-secret"
        ),
    )

    return app, input_root


def test_successful_readiness_updates_metrics(
    tmp_path,
):
    app, _ = build_app(tmp_path)
    client = TestClient(app)

    response = client.get(
        "/health/ready"
    )

    assert response.status_code == 200

    snapshot = (
        app.state.operational_metrics.snapshot()
    )

    assert snapshot["health"][
        "readiness_checks_total"
    ] == 1

    assert snapshot["health"][
        "readiness_failures_total"
    ] == 0

    assert snapshot["health"][
        "readiness_failures_by_component"
    ] == {}


def test_failed_readiness_updates_metrics(
    tmp_path,
):
    app, input_root = build_app(tmp_path)
    shutil.rmtree(input_root)

    client = TestClient(app)

    first = client.get(
        "/health/ready"
    )
    second = client.get(
        "/health/ready"
    )

    assert first.status_code == 503
    assert second.status_code == 503

    snapshot = (
        app.state.operational_metrics.snapshot()
    )

    assert snapshot["health"][
        "readiness_checks_total"
    ] == 2

    assert snapshot["health"][
        "readiness_failures_total"
    ] == 2

    assert snapshot["health"][
        "readiness_failures_by_component"
    ]["input_root"] == 2


def test_failed_readiness_emits_structured_log(
    tmp_path,
    caplog,
):
    app, input_root = build_app(tmp_path)
    shutil.rmtree(input_root)

    client = TestClient(app)

    supplied_request_id = (
        "readiness-failure-request-01"
    )

    with caplog.at_level(
        logging.WARNING,
        logger="soc.health",
    ):
        response = client.get(
            "/health/ready",
            headers={
                "X-Request-ID": (
                    supplied_request_id
                )
            },
        )

    assert response.status_code == 503

    records = [
        record
        for record in caplog.records
        if getattr(
            record,
            "event_type",
            None,
        )
        == "service_readiness_failed"
    ]

    assert len(records) == 1

    record = records[0]

    assert record.request_id == (
        supplied_request_id
    )
    assert record.status_code == 503
    assert record.failed_checks == [
        "input_root"
    ]
    assert record.failed_check_count == 1


def test_healthy_readiness_does_not_log_warning(
    tmp_path,
    caplog,
):
    app, _ = build_app(tmp_path)
    client = TestClient(app)

    with caplog.at_level(
        logging.WARNING,
        logger="soc.health",
    ):
        response = client.get(
            "/health/ready"
        )

    assert response.status_code == 200

    assert not any(
        getattr(
            record,
            "event_type",
            None,
        )
        == "service_readiness_failed"
        for record in caplog.records
    )


def test_metrics_openapi_documentation_exists(
    tmp_path,
):
    app, _ = build_app(tmp_path)
    client = TestClient(app)

    response = client.get(
        "/openapi.json"
    )

    assert response.status_code == 200

    paths = response.json()["paths"]

    assert "/health/live" in paths
    assert "/health/ready" in paths
    assert "/metrics" in paths

    metrics_operation = paths[
        "/metrics"
    ]["get"]

    assert metrics_operation["summary"] == (
        "Get operational metrics"
    )

    assert "401" in metrics_operation[
        "responses"
    ]
    assert "429" in metrics_operation[
        "responses"
    ]
