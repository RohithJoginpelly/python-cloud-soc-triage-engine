"""Safe structured security-event logging."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import Request

from src.api.observability import (
    current_request_id,
)


SECURITY_LOGGER = logging.getLogger(
    "soc.security"
)

FORBIDDEN_FIELD_FRAGMENTS = {
    "password",
    "api_key",
    "apikey",
    "secret",
    "token",
    "authorization",
    "cookie",
    "credential",
    "session_id",
}

ALLOWED_LOG_LEVELS = {
    logging.INFO,
    logging.WARNING,
    logging.ERROR,
    logging.CRITICAL,
}


def _safe_field_name(
    field_name: str,
) -> bool:
    """Return whether a structured field is safe."""

    normalized = field_name.strip().lower()

    if not normalized:
        return False

    return not any(
        fragment in normalized
        for fragment in FORBIDDEN_FIELD_FRAGMENTS
    )


def _request_id(
    request: Request | None,
) -> str | None:
    """Return the active request ID."""

    if request is not None:
        state_request_id = getattr(
            request.state,
            "request_id",
            None,
        )

        if isinstance(
            state_request_id,
            str,
        ):
            return state_request_id

    return current_request_id()


def emit_security_event(
    event_type: str,
    *,
    request: Request | None = None,
    level: int = logging.INFO,
    message: str = "Security event",
    **fields: Any,
) -> None:
    """Emit one structured, secret-safe event."""

    normalized_event_type = (
        event_type.strip().lower()
    )

    if not normalized_event_type:
        raise ValueError(
            "A security event type is required."
        )

    if level not in ALLOWED_LOG_LEVELS:
        raise ValueError(
            "Unsupported security log level."
        )

    structured_fields: dict[str, Any] = {
        "event_type": normalized_event_type,
    }

    request_id = _request_id(request)

    if request_id:
        structured_fields[
            "request_id"
        ] = request_id

    if request is not None:
        structured_fields.update(
            {
                "method": request.method,
                "path": request.url.path,
            }
        )

    for field_name, field_value in (
        fields.items()
    ):
        if not _safe_field_name(
            field_name
        ):
            continue

        structured_fields[
            field_name
        ] = field_value

    if request is not None:
        application_state = getattr(
            request.app,
            "state",
            None,
        )

        metrics = getattr(
            application_state,
            "operational_metrics",
            None,
        )

        metrics_recorder = getattr(
            metrics,
            "record_security_event",
            None,
        )

        if callable(metrics_recorder):
            metrics_recorder(
                normalized_event_type
            )

    SECURITY_LOGGER.log(
        level,
        message,
        extra=structured_fields,
    )
