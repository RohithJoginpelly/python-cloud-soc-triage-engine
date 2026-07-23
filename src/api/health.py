"""Operational liveness and readiness checks."""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import Literal

from fastapi import (
    APIRouter,
    Request,
    Response,
    status,
)
from pydantic import BaseModel


HEALTH_LOGGER = logging.getLogger(
    "soc.health"
)


class LivenessResponse(BaseModel):
    """Response returned by the liveness endpoint."""

    status: Literal["alive"]
    service: str
    version: str


class ComponentHealth(BaseModel):
    """Health status for one application dependency."""

    status: Literal[
        "healthy",
        "unhealthy",
    ]
    reason: str | None = None


class ReadinessResponse(BaseModel):
    """Response returned by the readiness endpoint."""

    status: Literal[
        "ready",
        "not_ready",
    ]
    service: str
    version: str
    checks: dict[str, ComponentHealth]


class ReadinessChecker:
    """Check dependencies needed to serve SOC requests."""

    def __init__(
        self,
        *,
        database_path: str | Path,
        input_root: str | Path,
        database_timeout_seconds: float = 1.0,
    ) -> None:
        self.database_path = Path(
            database_path
        )
        self.input_root = Path(input_root)
        self.database_timeout_seconds = (
            database_timeout_seconds
        )

    def _check_database(
        self,
    ) -> ComponentHealth:
        """Confirm that SQLite accepts a basic query."""

        connection: sqlite3.Connection | None = (
            None
        )

        try:
            connection = sqlite3.connect(
                str(self.database_path),
                timeout=(
                    self.database_timeout_seconds
                ),
            )

            result = connection.execute(
                "SELECT 1"
            ).fetchone()

            if result != (1,):
                return ComponentHealth(
                    status="unhealthy",
                    reason=(
                        "database_check_failed"
                    ),
                )
        except sqlite3.Error:
            return ComponentHealth(
                status="unhealthy",
                reason="database_unavailable",
            )
        finally:
            if connection is not None:
                connection.close()

        return ComponentHealth(
            status="healthy"
        )

    def _check_input_root(
        self,
    ) -> ComponentHealth:
        """Confirm the telemetry input directory exists."""

        try:
            if (
                not self.input_root.exists()
                or not self.input_root.is_dir()
            ):
                return ComponentHealth(
                    status="unhealthy",
                    reason=(
                        "input_root_unavailable"
                    ),
                )
        except OSError:
            return ComponentHealth(
                status="unhealthy",
                reason="input_root_unavailable",
            )

        return ComponentHealth(
            status="healthy"
        )

    def check(
        self,
    ) -> dict[str, ComponentHealth]:
        """Run all readiness dependency checks."""

        return {
            "database": (
                self._check_database()
            ),
            "input_root": (
                self._check_input_root()
            ),
        }


router = APIRouter(
    tags=["system"],
)


@router.get(
    "/health/live",
    response_model=LivenessResponse,
)
def liveness(
    request: Request,
) -> LivenessResponse:
    """Return process liveness without dependency checks."""

    return LivenessResponse(
        status="alive",
        service="ai-soc-copilot",
        version=request.app.version,
    )


@router.get(
    "/health/ready",
    response_model=ReadinessResponse,
    responses={
        status.HTTP_503_SERVICE_UNAVAILABLE: {
            "description": (
                "One or more required dependencies "
                "are unavailable."
            )
        }
    },
)
def readiness(
    request: Request,
    response: Response,
) -> ReadinessResponse:
    """Return dependency readiness for traffic routing."""

    checker: ReadinessChecker = (
        request.app.state.readiness_checker
    )

    checks = checker.check()

    failed_checks = tuple(
        sorted(
            component_name
            for component_name, component
            in checks.items()
            if component.status != "healthy"
        )
    )

    ready = not failed_checks

    metrics = getattr(
        request.app.state,
        "operational_metrics",
        None,
    )

    metrics_recorder = getattr(
        metrics,
        "record_readiness_check",
        None,
    )

    if callable(metrics_recorder):
        metrics_recorder(
            ready=ready,
            failed_checks=failed_checks,
        )

    if not ready:
        response.status_code = (
            status.HTTP_503_SERVICE_UNAVAILABLE
        )

        request_id = getattr(
            request.state,
            "request_id",
            None,
        )

        log_fields = {
            "event_type": (
                "service_readiness_failed"
            ),
            "status_code": 503,
            "failed_checks": list(
                failed_checks
            ),
            "failed_check_count": len(
                failed_checks
            ),
        }

        if isinstance(request_id, str):
            log_fields["request_id"] = (
                request_id
            )

        HEALTH_LOGGER.warning(
            "Service readiness check failed",
            extra=log_fields,
        )

    return ReadinessResponse(
        status=(
            "ready"
            if ready
            else "not_ready"
        ),
        service="ai-soc-copilot",
        version=request.app.version,
        checks=checks,
    )
