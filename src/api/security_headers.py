"""HTTP security headers for the SOC API and dashboard."""

from __future__ import annotations

from starlette.types import (
    ASGIApp,
    Message,
    Receive,
    Scope,
    Send,
)


BASELINE_CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "object-src 'none'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "style-src 'self'; "
    "script-src 'self'; "
    "connect-src 'self'"
)

BASE_SECURITY_HEADERS = (
    (
        b"content-security-policy",
        BASELINE_CONTENT_SECURITY_POLICY.encode(
            "ascii"
        ),
    ),
    (
        b"x-frame-options",
        b"DENY",
    ),
    (
        b"x-content-type-options",
        b"nosniff",
    ),
    (
        b"referrer-policy",
        b"no-referrer",
    ),
    (
        b"permissions-policy",
        (
            b"camera=(), microphone=(), "
            b"geolocation=(), payment=(), "
            b"usb=()"
        ),
    ),
)

HSTS_HEADER = (
    b"strict-transport-security",
    b"max-age=31536000; includeSubDomains",
)


class SecurityHeadersMiddleware:
    """Attach defensive headers to HTTP responses."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        enable_hsts: bool = False,
    ) -> None:
        self.app = app
        self.enable_hsts = enable_hsts

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

        async def send_with_headers(
            message: Message,
        ) -> None:
            if (
                message["type"]
                == "http.response.start"
            ):
                headers = list(
                    message.get("headers", [])
                )

                existing_names = {
                    name.lower()
                    for name, _ in headers
                }

                for name, value in (
                    BASE_SECURITY_HEADERS
                ):
                    if name not in existing_names:
                        headers.append(
                            (name, value)
                        )

                request_scheme = str(
                    scope.get("scheme", "")
                ).lower()

                if (
                    self.enable_hsts
                    and request_scheme == "https"
                    and HSTS_HEADER[0]
                    not in existing_names
                ):
                    headers.append(
                        HSTS_HEADER
                    )

                message["headers"] = headers

            await send(message)

        await self.app(
            scope,
            receive,
            send_with_headers,
        )
