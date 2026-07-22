"""Request body size protection for the SOC application."""

from __future__ import annotations

from starlette.responses import JSONResponse
from starlette.types import (
    ASGIApp,
    Message,
    Receive,
    Scope,
    Send,
)


DEFAULT_MAX_REQUEST_BODY_BYTES = (
    2 * 1024 * 1024
)

BODY_METHODS = {
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
}


class RequestBodyTooLarge(Exception):
    """Raised when a request exceeds the body limit."""


def _content_length(
    scope: Scope,
) -> int | None:
    """Read a valid Content-Length from an ASGI scope."""

    for name, value in scope.get(
        "headers",
        [],
    ):
        if name.lower() != b"content-length":
            continue

        try:
            parsed = int(
                value.decode("ascii")
            )
        except (
            UnicodeDecodeError,
            ValueError,
        ):
            return None

        if parsed < 0:
            return None

        return parsed

    return None


class RequestBodyLimitMiddleware:
    """Reject oversized HTTP request bodies."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_body_bytes: int = (
            DEFAULT_MAX_REQUEST_BODY_BYTES
        ),
    ) -> None:
        if max_body_bytes < 1:
            raise ValueError(
                "max_body_bytes must be at least one."
            )

        self.app = app
        self.max_body_bytes = max_body_bytes

    async def _reject(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """Return a consistent 413 response."""

        response = JSONResponse(
            status_code=413,
            content={
                "detail": (
                    "Request body exceeds the "
                    "configured size limit."
                )
            },
            headers={
                "X-Max-Request-Body-Bytes": str(
                    self.max_body_bytes
                )
            },
        )

        await response(
            scope,
            receive,
            send,
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

        method = str(
            scope.get("method", "")
        ).upper()

        if method not in BODY_METHODS:
            await self.app(
                scope,
                receive,
                send,
            )
            return

        declared_length = _content_length(
            scope
        )

        if (
            declared_length is not None
            and declared_length
            > self.max_body_bytes
        ):
            await self._reject(
                scope,
                receive,
                send,
            )
            return

        received_bytes = 0

        async def limited_receive() -> Message:
            nonlocal received_bytes

            message = await receive()

            if message["type"] != "http.request":
                return message

            body = message.get(
                "body",
                b"",
            )

            received_bytes += len(body)

            if (
                received_bytes
                > self.max_body_bytes
            ):
                raise RequestBodyTooLarge

            return message

        try:
            await self.app(
                scope,
                limited_receive,
                send,
            )
        except RequestBodyTooLarge:
            await self._reject(
                scope,
                receive,
                send,
            )
