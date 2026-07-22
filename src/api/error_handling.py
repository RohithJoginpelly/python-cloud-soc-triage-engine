"""Production-safe handling of unexpected application errors."""

from __future__ import annotations

import logging
import secrets

from fastapi import FastAPI, Request
from starlette.responses import (
    HTMLResponse,
    JSONResponse,
    Response,
)

from src.api.security_headers import (
    BASE_SECURITY_HEADERS,
    HSTS_HEADER,
)


LOGGER = logging.getLogger(__name__)

GENERIC_ERROR_MESSAGE = (
    "An unexpected server error occurred."
)


def _error_reference() -> str:
    """Create a non-sensitive incident reference."""

    return secrets.token_hex(12)


def _is_dashboard_request(
    request: Request,
) -> bool:
    """Return whether an HTML dashboard response is expected."""

    path = request.url.path

    return (
        path == "/dashboard"
        or path.startswith("/dashboard/")
    )


def _response_headers(
    request: Request,
    error_reference: str,
) -> dict[str, str]:
    """Build defensive headers for unexpected errors."""

    headers = {
        "Cache-Control": "no-store",
        "X-Error-Reference": error_reference,
    }

    for name, value in BASE_SECURITY_HEADERS:
        headers[
            name.decode("ascii")
        ] = value.decode("ascii")

    hsts_enabled = bool(
        getattr(
            request.app.state,
            "hsts_enabled",
            False,
        )
    )

    request_scheme = str(
        request.scope.get("scheme", "")
    ).lower()

    if (
        hsts_enabled
        and request_scheme == "https"
    ):
        headers[
            HSTS_HEADER[0].decode("ascii")
        ] = HSTS_HEADER[1].decode("ascii")

    return headers


def _dashboard_error_response(
    request: Request,
    error_reference: str,
) -> HTMLResponse:
    """Return a generic dashboard error page."""

    return HTMLResponse(
        status_code=500,
        headers=_response_headers(
            request,
            error_reference,
        ),
        content=(
            "<!DOCTYPE html>"
            '<html lang="en">'
            "<head>"
            '<meta charset="UTF-8">'
            "<meta name=\"viewport\" "
            'content="width=device-width, '
            'initial-scale=1">'
            "<title>Unexpected Error</title>"
            "</head>"
            "<body>"
            "<main>"
            "<h1>Unexpected error</h1>"
            "<p>The request could not be completed.</p>"
            "<p>Error reference: "
            f"<code>{error_reference}</code>"
            "</p>"
            "</main>"
            "</body>"
            "</html>"
        ),
    )


def _api_error_response(
    request: Request,
    error_reference: str,
) -> JSONResponse:
    """Return a generic JSON error response."""

    return JSONResponse(
        status_code=500,
        headers=_response_headers(
            request,
            error_reference,
        ),
        content={
            "detail": GENERIC_ERROR_MESSAGE,
            "error_reference": error_reference,
        },
    )


async def safe_unhandled_exception_handler(
    request: Request,
    error: Exception,
) -> Response:
    """Log an unexpected error without exposing it."""

    error_reference = _error_reference()

    LOGGER.error(
        (
            "Unhandled application exception "
            "reference=%s method=%s path=%s"
        ),
        error_reference,
        request.method,
        request.url.path,
        exc_info=(
            type(error),
            error,
            error.__traceback__,
        ),
    )

    if _is_dashboard_request(request):
        return _dashboard_error_response(
            request,
            error_reference,
        )

    return _api_error_response(
        request,
        error_reference,
    )


def configure_safe_error_handling(
    app: FastAPI,
) -> None:
    """Register production-safe exception handling."""

    app.add_exception_handler(
        Exception,
        safe_unhandled_exception_handler,
    )
