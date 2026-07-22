"""Structured security-event logging tests."""

from __future__ import annotations

import logging

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.api.observability import (
    RequestObservabilityMiddleware,
)
from src.api.security_events import (
    emit_security_event,
)


def build_app() -> FastAPI:
    """Create an isolated logging test app."""

    app = FastAPI()

    app.add_middleware(
        RequestObservabilityMiddleware
    )

    @app.get("/security-event")
    def security_event(
        request: Request,
    ):
        emit_security_event(
            "login_failed",
            request=request,
            level=logging.WARNING,
            message="Analyst login failed",
            client_address="192.0.2.10",
            status_code=401,
            outcome="denied",
            reason="invalid_credentials",
        )

        return {"status": "logged"}

    @app.get("/sensitive-event")
    def sensitive_event(
        request: Request,
    ):
        emit_security_event(
            "authentication_test",
            request=request,
            password=(
                "Sensitive-Password-2026!"
            ),
            api_key="private-api-key",
            session_id="private-session",
            access_token="private-token",
            client_address="192.0.2.20",
        )

        return {"status": "logged"}

    return app


def test_security_event_contains_request_context(
    caplog,
):
    app = build_app()
    client = TestClient(app)

    with caplog.at_level(
        logging.WARNING,
        logger="soc.security",
    ):
        response = client.get(
            "/security-event",
            headers={
                "X-Request-ID": (
                    "security-request-2026"
                )
            },
        )

    assert response.status_code == 200

    matching_records = [
        record
        for record in caplog.records
        if getattr(
            record,
            "event_type",
            None,
        )
        == "login_failed"
    ]

    assert len(matching_records) == 1

    record = matching_records[0]

    assert record.request_id == (
        "security-request-2026"
    )
    assert record.method == "GET"
    assert record.path == (
        "/security-event"
    )
    assert record.client_address == (
        "192.0.2.10"
    )
    assert record.status_code == 401
    assert record.outcome == "denied"
    assert record.reason == (
        "invalid_credentials"
    )


def test_sensitive_fields_are_not_logged(
    caplog,
):
    app = build_app()
    client = TestClient(app)

    with caplog.at_level(
        logging.INFO,
        logger="soc.security",
    ):
        response = client.get(
            "/sensitive-event"
        )

    assert response.status_code == 200

    record = next(
        record
        for record in caplog.records
        if getattr(
            record,
            "event_type",
            None,
        )
        == "authentication_test"
    )

    assert not hasattr(
        record,
        "password",
    )
    assert not hasattr(
        record,
        "api_key",
    )
    assert not hasattr(
        record,
        "session_id",
    )
    assert not hasattr(
        record,
        "access_token",
    )

    assert record.client_address == (
        "192.0.2.20"
    )

    serialized_record = str(
        record.__dict__
    )

    assert (
        "Sensitive-Password-2026!"
        not in serialized_record
    )
    assert (
        "private-api-key"
        not in serialized_record
    )
    assert (
        "private-session"
        not in serialized_record
    )
    assert (
        "private-token"
        not in serialized_record
    )


def test_event_type_is_normalized(
    caplog,
):
    with caplog.at_level(
        logging.INFO,
        logger="soc.security",
    ):
        emit_security_event(
            "  API_RATE_LIMITED  ",
            status_code=429,
        )

    record = caplog.records[-1]

    assert record.event_type == (
        "api_rate_limited"
    )


def test_empty_event_type_is_rejected():
    with pytest.raises(
        ValueError,
        match="event type is required",
    ):
        emit_security_event("   ")


def test_unsupported_log_level_is_rejected():
    with pytest.raises(
        ValueError,
        match="Unsupported security log level",
    ):
        emit_security_event(
            "test_event",
            level=logging.DEBUG,
        )
