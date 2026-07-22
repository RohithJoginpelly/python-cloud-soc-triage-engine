"""Structured logging and request correlation for the SOC API."""

from __future__ import annotations

import contextvars
import json
import logging
import re
import secrets
import time
from datetime import datetime, timezone
from typing import Any

from starlette.types import (
    ASGIApp,
    Message,
    Receive,
    Scope,
    Send,
)


REQUEST_ID_HEADER = b"x-request-id"
MAX_REQUEST_ID_LENGTH = 128

REQUEST_ID_PATTERN = re.compile(
    r"^[A-Za-z0-9._-]+$"
)

request_id_context: contextvars.ContextVar[
    str | None
] = contextvars.ContextVar(
    "soc_request_id",
    default=None,
)


def generate_request_id() -> str:
    """Generate a cryptographically random request ID."""

    return secrets.token_hex(16)


def normalize_request_id(
    value: str | None,
) -> str:
    """Accept a safe request ID or generate a new one."""

    if not isinstance(value, str):
        return generate_request_id()

    normalized = value.strip()

    if (
        not normalized
        or len(normalized)
        > MAX_REQUEST_ID_LENGTH
        or REQUEST_ID_PATTERN.fullmatch(
            normalized
        )
        is None
    ):
        return generate_request_id()

    return normalized


def current_request_id() -> str | None:
    """Return the request ID for the active context."""

    return request_id_context.get()


def request_id_from_scope(
    scope: Scope,
) -> str:
    """Resolve an incoming request ID from ASGI headers."""

    incoming_value: str | None = None

    for name, value in scope.get(
        "headers",
        [],
    ):
        if name.lower() != REQUEST_ID_HEADER:
            continue

        try:
            incoming_value = value.decode(
                "ascii"
            )
        except UnicodeDecodeError:
            incoming_value = None

        break

    return normalize_request_id(
        incoming_value
    )


class StructuredJSONFormatter(
    logging.Formatter
):
    """Format application logs as one JSON object per line."""

    RESERVED_FIELDS = {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "thread",
        "threadName",
        "taskName",
    }

    def format(
        self,
        record: logging.LogRecord,
    ) -> str:
        """Serialize one log record as JSON."""

        payload: dict[str, Any] = {
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        request_id = getattr(
            record,
            "request_id",
            None,
        ) or current_request_id()

        if request_id:
            payload["request_id"] = (
                request_id
            )

        for field_name, field_value in (
            record.__dict__.items()
        ):
            if (
                field_name
                in self.RESERVED_FIELDS
                or field_name.startswith("_")
                or field_name
                in payload
            ):
                continue

            try:
                json.dumps(field_value)
                payload[field_name] = (
                    field_value
                )
            except (
                TypeError,
                ValueError,
            ):
                payload[field_name] = str(
                    field_value
                )

        if record.exc_info:
            payload["exception_type"] = (
                record.exc_info[0].__name__
            )

        return json.dumps(
            payload,
            separators=(",", ":"),
            sort_keys=True,
        )


class RequestObservabilityMiddleware:
    """Attach request IDs and emit structured request events."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        logger: logging.Logger | None = None,
    ) -> None:
        self.app = app
        self.logger = (
            logger
            or logging.getLogger(
                "soc.http"
            )
        )

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http":
            await self.app(
                scope,
                receive,
                send,
            )
            return

        request_id = request_id_from_scope(
            scope
        )

        state = scope.setdefault(
            "state",
            {},
        )

        state["request_id"] = request_id

        token = request_id_context.set(
            request_id
        )

        started_at = time.perf_counter()
        response_status = 500
        response_started = False

        async def send_with_request_id(
            message: Message,
        ) -> None:
            nonlocal response_status
            nonlocal response_started

            if (
                message["type"]
                == "http.response.start"
            ):
                response_started = True
                response_status = int(
                    message["status"]
                )

                headers = list(
                    message.get(
                        "headers",
                        [],
                    )
                )

                existing_names = {
                    name.lower()
                    for name, _ in headers
                }

                if (
                    REQUEST_ID_HEADER
                    not in existing_names
                ):
                    headers.append(
                        (
                            REQUEST_ID_HEADER,
                            request_id.encode(
                                "ascii"
                            ),
                        )
                    )

                message["headers"] = headers

            await send(message)

        try:
            await self.app(
                scope,
                receive,
                send_with_request_id,
            )
        except Exception:
            duration_ms = round(
                (
                    time.perf_counter()
                    - started_at
                )
                * 1000,
                3,
            )

            self.logger.error(
                "HTTP request failed",
                extra={
                    "event_type": (
                        "http_request_failed"
                    ),
                    "request_id": request_id,
                    "method": scope.get(
                        "method",
                        "",
                    ),
                    "path": scope.get(
                        "path",
                        "",
                    ),
                    "status_code": (
                        response_status
                        if response_started
                        else 500
                    ),
                    "duration_ms": duration_ms,
                },
                exc_info=True,
            )

            raise
        else:
            duration_ms = round(
                (
                    time.perf_counter()
                    - started_at
                )
                * 1000,
                3,
            )

            self.logger.info(
                "HTTP request completed",
                extra={
                    "event_type": (
                        "http_request_completed"
                    ),
                    "request_id": request_id,
                    "method": scope.get(
                        "method",
                        "",
                    ),
                    "path": scope.get(
                        "path",
                        "",
                    ),
                    "status_code": (
                        response_status
                    ),
                    "duration_ms": duration_ms,
                },
            )
        finally:
            request_id_context.reset(
                token
            )
