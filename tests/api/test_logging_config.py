"""Application structured logging configuration tests."""

from __future__ import annotations

import io
import json
import logging

import pytest

from src.api.logging_config import (
    MANAGED_LOGGERS,
    configure_application_logging,
)
from src.api.security_events import (
    emit_security_event,
)


def restore_text_logging() -> None:
    """Restore normal test logging behavior."""

    configure_application_logging(
        log_format="text",
        level_name="INFO",
    )


def test_json_logging_emits_one_json_object():
    stream = io.StringIO()

    try:
        configuration = (
            configure_application_logging(
                log_format="json",
                level_name="INFO",
                stream=stream,
            )
        )

        emit_security_event(
            "api_rate_limited",
            level=logging.WARNING,
            message=(
                "Protected API request "
                "rate limited"
            ),
            client_address="192.0.2.10",
            status_code=429,
            outcome="blocked",
        )

        lines = [
            line
            for line in stream.getvalue()
            .splitlines()
            if line.strip()
        ]

        assert len(lines) == 1

        payload = json.loads(
            lines[0]
        )

        assert configuration.log_format == (
            "json"
        )
        assert configuration.level_name == (
            "INFO"
        )

        assert payload["level"] == "WARNING"
        assert payload["logger"] == (
            "soc.security"
        )
        assert payload["event_type"] == (
            "api_rate_limited"
        )
        assert payload["status_code"] == 429
        assert payload["outcome"] == (
            "blocked"
        )
        assert payload["client_address"] == (
            "192.0.2.10"
        )
        assert "timestamp" in payload
    finally:
        restore_text_logging()


def test_configured_level_filters_lower_events():
    stream = io.StringIO()

    try:
        configure_application_logging(
            log_format="json",
            level_name="ERROR",
            stream=stream,
        )

        emit_security_event(
            "informational_event",
            level=logging.INFO,
        )

        emit_security_event(
            "security_failure",
            level=logging.ERROR,
            status_code=500,
        )

        lines = [
            line
            for line in stream.getvalue()
            .splitlines()
            if line.strip()
        ]

        assert len(lines) == 1

        payload = json.loads(
            lines[0]
        )

        assert payload["event_type"] == (
            "security_failure"
        )
        assert payload["level"] == "ERROR"
    finally:
        restore_text_logging()


def test_text_mode_removes_structured_handlers():
    stream = io.StringIO()

    configure_application_logging(
        log_format="json",
        level_name="INFO",
        stream=stream,
    )

    restore_text_logging()

    for logger_name in MANAGED_LOGGERS:
        logger = logging.getLogger(
            logger_name
        )

        assert logger.propagate is True

        assert not any(
            getattr(
                handler,
                "_soc_structured_handler",
                False,
            )
            for handler in logger.handlers
        )


def test_environment_configuration_is_supported(
    monkeypatch,
):
    monkeypatch.setenv(
        "SOC_LOG_FORMAT",
        "text",
    )

    monkeypatch.setenv(
        "SOC_LOG_LEVEL",
        "WARNING",
    )

    configuration = (
        configure_application_logging()
    )

    assert configuration.log_format == (
        "text"
    )
    assert configuration.level_name == (
        "WARNING"
    )
    assert configuration.level == (
        logging.WARNING
    )


def test_invalid_log_format_is_rejected():
    with pytest.raises(
        ValueError,
        match="SOC_LOG_FORMAT",
    ):
        configure_application_logging(
            log_format="xml",
        )


def test_invalid_log_level_is_rejected():
    with pytest.raises(
        ValueError,
        match="SOC_LOG_LEVEL",
    ):
        configure_application_logging(
            level_name="VERBOSE",
        )
