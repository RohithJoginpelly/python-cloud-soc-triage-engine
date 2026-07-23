"""Structured logging and request-ID tests."""

from __future__ import annotations

import json
import logging
import re

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.api.observability import (
    RequestObservabilityMiddleware,
    StructuredJSONFormatter,
    current_request_id,
    normalize_request_id,
)


HEX_REQUEST_ID_PATTERN = re.compile(
    r"^[0-9a-f]{32}$"
)


def build_app() -> FastAPI:
    """Create a small observability test app."""

    app = FastAPI()

    app.add_middleware(
        RequestObservabilityMiddleware
    )

    @app.get("/request-id")
    def request_id_route(
        request: Request,
    ):
        return {
            "scope_request_id": (
                request.state.request_id
            ),
            "context_request_id": (
                current_request_id()
            ),
        }

    return app


def test_safe_incoming_request_id_is_preserved():
    app = build_app()
    client = TestClient(app)

    response = client.get(
        "/request-id",
        headers={
            "X-Request-ID": (
                "soc-request-2026_01"
            )
        },
    )

    assert response.status_code == 200

    assert response.headers[
        "x-request-id"
    ] == "soc-request-2026_01"

    assert response.json() == {
        "scope_request_id": (
            "soc-request-2026_01"
        ),
        "context_request_id": (
            "soc-request-2026_01"
        ),
    }


def test_missing_request_id_is_generated():
    app = build_app()
    client = TestClient(app)

    response = client.get(
        "/request-id"
    )

    request_id = response.headers[
        "x-request-id"
    ]

    assert HEX_REQUEST_ID_PATTERN.fullmatch(
        request_id
    )

    assert response.json()[
        "scope_request_id"
    ] == request_id

    assert response.json()[
        "context_request_id"
    ] == request_id


def test_unsafe_request_id_is_replaced():
    app = build_app()
    client = TestClient(app)

    response = client.get(
        "/request-id",
        headers={
            "X-Request-ID": (
                "bad request id\r\nInjected: yes"
            )
        },
    )

    assert response.status_code == 200

    request_id = response.headers[
        "x-request-id"
    ]

    assert request_id != (
        "bad request id\r\nInjected: yes"
    )

    assert HEX_REQUEST_ID_PATTERN.fullmatch(
        request_id
    )


def test_excessively_long_request_id_is_replaced():
    normalized = normalize_request_id(
        "A" * 129
    )

    assert HEX_REQUEST_ID_PATTERN.fullmatch(
        normalized
    )


def test_json_formatter_emits_structured_fields():
    formatter = StructuredJSONFormatter()

    record = logging.LogRecord(
        name="soc.security",
        level=logging.WARNING,
        pathname=__file__,
        lineno=100,
        msg="Login request blocked",
        args=(),
        exc_info=None,
    )

    record.request_id = (
        "request-123"
    )
    record.event_type = (
        "login_rate_limited"
    )
    record.client_address = (
        "192.0.2.10"
    )
    record.status_code = 429

    payload = json.loads(
        formatter.format(record)
    )

    assert payload[
        "level"
    ] == "WARNING"

    assert payload[
        "logger"
    ] == "soc.security"

    assert payload[
        "message"
    ] == "Login request blocked"

    assert payload[
        "request_id"
    ] == "request-123"

    assert payload[
        "event_type"
    ] == "login_rate_limited"

    assert payload[
        "client_address"
    ] == "192.0.2.10"

    assert payload[
        "status_code"
    ] == 429

    assert "timestamp" in payload


def test_request_completion_event_is_logged(
    caplog,
):
    app = build_app()
    client = TestClient(app)

    with caplog.at_level(
        logging.INFO,
        logger="soc.http",
    ):
        response = client.get(
            "/request-id"
        )

    request_id = response.headers[
        "x-request-id"
    ]

    matching_records = [
        record
        for record in caplog.records
        if getattr(
            record,
            "event_type",
            None,
        )
        == "http_request_completed"
    ]

    assert len(matching_records) == 1

    record = matching_records[0]

    assert record.request_id == request_id
    assert record.method == "GET"
    assert record.path == "/request-id"
    assert record.status_code == 200
    assert record.duration_ms >= 0
