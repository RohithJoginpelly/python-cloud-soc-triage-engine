"""Authentication middleware for the SOC API."""

from __future__ import annotations

from hmac import compare_digest

from fastapi import FastAPI, Request
from starlette.responses import JSONResponse


PUBLIC_PATHS = {
    "/",
    "/health",
    "/docs",
    "/docs/oauth2-redirect",
    "/redoc",
    "/openapi.json",
}

PUBLIC_PREFIXES = {
    "/dashboard",
    "/static",
}


def _is_public_path(path: str) -> bool:
    """Return True when middleware authentication is skipped."""

    if path in PUBLIC_PATHS:
        return True

    return any(
        path == prefix
        or path.startswith(f"{prefix}/")
        for prefix in PUBLIC_PREFIXES
    )


def configure_api_key_auth(app: FastAPI) -> None:
    """Require an API key for protected JSON API endpoints."""

    @app.middleware("http")
    async def require_api_key(
        request: Request,
        call_next,
    ):
        """Authenticate requests before route processing."""

        if _is_public_path(request.url.path):
            return await call_next(request)

        configured_key = getattr(
            request.app.state,
            "api_key",
            None,
        )

        if (
            not isinstance(configured_key, str)
            or not configured_key
        ):
            return JSONResponse(
                status_code=503,
                content={
                    "detail": (
                        "SOC API authentication is not configured"
                    )
                },
            )

        provided_key = request.headers.get(
            "X-SOC-API-Key"
        )

        if (
            not isinstance(provided_key, str)
            or not provided_key
            or not compare_digest(
                provided_key.encode("utf-8"),
                configured_key.encode("utf-8"),
            )
        ):
            return JSONResponse(
                status_code=401,
                content={
                    "detail": (
                        "Invalid or missing SOC API key"
                    )
                },
                headers={
                    "WWW-Authenticate": "ApiKey"
                },
            )

        return await call_next(request)
