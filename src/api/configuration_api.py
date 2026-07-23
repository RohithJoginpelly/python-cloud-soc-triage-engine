"""Protected runtime configuration status endpoint."""

from __future__ import annotations

from typing import Any

from fastapi import (
    APIRouter,
    Request,
    Response,
)

from src.api.configuration import (
    ConfigurationReport,
)


router = APIRouter(
    tags=["system"],
)


@router.get(
    "/configuration",
    summary="Get safe runtime configuration status",
    description=(
        "Return a secret-free runtime configuration "
        "validation report. This endpoint requires a "
        "valid X-SOC-API-Key header."
    ),
    responses={
        401: {
            "description": (
                "Missing or invalid SOC API key."
            )
        },
        429: {
            "description": (
                "Operational API rate limit exceeded."
            )
        },
    },
)
def configuration_status(
    request: Request,
    response: Response,
) -> dict[str, Any]:
    """Return only non-sensitive configuration status."""

    response.headers[
        "Cache-Control"
    ] = "no-store"

    report: ConfigurationReport = (
        request.app.state.configuration_report
    )

    return {
        "status": (
            "valid"
            if report.valid
            else "invalid"
        ),
        "service": "ai-soc-copilot",
        "version": request.app.version,
        "configuration": (
            report.to_safe_dict()
        ),
    }
