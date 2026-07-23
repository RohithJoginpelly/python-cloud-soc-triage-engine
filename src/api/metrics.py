"""Safe in-memory operational metrics for the SOC API."""

from __future__ import annotations

import threading
import time
from collections import Counter
from typing import Any

from fastapi import (
    APIRouter,
    Request,
    Response,
)


STATUS_CLASSES = (
    "1xx",
    "2xx",
    "3xx",
    "4xx",
    "5xx",
    "other",
)


class OperationalMetrics:
    """Maintain low-cardinality process-local counters."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._started_at = time.monotonic()

        self._http_requests_total = 0
        self._http_status_counts: Counter[str] = (
            Counter()
        )

        self._http_duration_ms_total = 0.0
        self._http_duration_ms_max = 0.0

        self._security_event_counts: Counter[str] = (
            Counter()
        )

        self._readiness_checks_total = 0
        self._readiness_failures_total = 0

        self._readiness_failure_counts: Counter[str] = (
            Counter()
        )

    @staticmethod
    def _status_class(
        status_code: int,
    ) -> str:
        """Return a bounded HTTP status category."""

        if 100 <= status_code <= 599:
            return f"{status_code // 100}xx"

        return "other"

    def record_http_request(
        self,
        *,
        status_code: int,
        duration_ms: float,
    ) -> None:
        """Record one completed HTTP request."""

        safe_duration = max(
            float(duration_ms),
            0.0,
        )

        status_class = self._status_class(
            int(status_code)
        )

        with self._lock:
            self._http_requests_total += 1

            self._http_status_counts[
                status_class
            ] += 1

            self._http_duration_ms_total += (
                safe_duration
            )

            self._http_duration_ms_max = max(
                self._http_duration_ms_max,
                safe_duration,
            )

    def record_security_event(
        self,
        event_type: str,
    ) -> None:
        """Record one internal security-event category."""

        normalized = event_type.strip().lower()

        if not normalized:
            return

        with self._lock:
            self._security_event_counts[
                normalized
            ] += 1

    def record_readiness_check(
        self,
        *,
        ready: bool,
        failed_checks: list[str] | tuple[str, ...] = (),
    ) -> None:
        """Record one dependency-readiness result."""

        normalized_failures = {
            str(component).strip().lower()
            for component in failed_checks
            if str(component).strip()
        }

        with self._lock:
            self._readiness_checks_total += 1

            if ready:
                return

            self._readiness_failures_total += 1

            for component in normalized_failures:
                self._readiness_failure_counts[
                    component
                ] += 1

    def snapshot(self) -> dict[str, Any]:
        """Return a consistent, secret-free snapshot."""

        with self._lock:
            requests_total = (
                self._http_requests_total
            )

            status_counts = {
                status_class: (
                    self._http_status_counts.get(
                        status_class,
                        0,
                    )
                )
                for status_class in STATUS_CLASSES
            }

            duration_total = (
                self._http_duration_ms_total
            )

            duration_max = (
                self._http_duration_ms_max
            )

            security_counts = dict(
                sorted(
                    self._security_event_counts.items()
                )
            )

            readiness_checks_total = (
                self._readiness_checks_total
            )

            readiness_failures_total = (
                self._readiness_failures_total
            )

            readiness_failure_counts = dict(
                sorted(
                    self._readiness_failure_counts.items()
                )
            )

        average_duration = (
            duration_total / requests_total
            if requests_total
            else 0.0
        )

        def security_total(
            *event_types: str,
        ) -> int:
            return sum(
                security_counts.get(
                    event_type,
                    0,
                )
                for event_type in event_types
            )

        uptime_seconds = max(
            time.monotonic()
            - self._started_at,
            0.0,
        )

        return {
            "uptime_seconds": round(
                uptime_seconds,
                3,
            ),
            "health": {
                "readiness_checks_total": (
                    readiness_checks_total
                ),
                "readiness_failures_total": (
                    readiness_failures_total
                ),
                "readiness_failures_by_component": (
                    readiness_failure_counts
                ),
            },
            "http": {
                "requests_total": requests_total,
                "responses_by_class": (
                    status_counts
                ),
                "client_errors_total": (
                    status_counts["4xx"]
                ),
                "server_errors_total": (
                    status_counts["5xx"]
                ),
                "duration_ms": {
                    "average": round(
                        average_duration,
                        3,
                    ),
                    "maximum": round(
                        duration_max,
                        3,
                    ),
                    "total": round(
                        duration_total,
                        3,
                    ),
                },
            },
            "security": {
                "events_total": sum(
                    security_counts.values()
                ),
                "authentication_denials_total": (
                    security_total(
                        "login_failed",
                        "login_blocked",
                        "api_authentication_failed",
                        (
                            "api_authentication_"
                            "unavailable"
                        ),
                    )
                ),
                "login_successes_total": (
                    security_total(
                        "login_succeeded"
                    )
                ),
                "account_lockouts_total": (
                    security_total(
                        "account_locked"
                    )
                ),
                "rate_limited_requests_total": (
                    security_total(
                        "login_rate_limited",
                        "api_rate_limited",
                    )
                ),
                "request_body_rejections_total": (
                    security_total(
                        "request_body_rejected"
                    )
                ),
                "events_by_type": security_counts,
            },
        }


router = APIRouter(
    tags=["system"],
)


@router.get(
    "/metrics",
    summary="Get operational metrics",
    description=(
        "Return protected, process-local operational "
        "metrics for HTTP traffic, readiness checks, "
        "and security-control events. This endpoint "
        "requires a valid X-SOC-API-Key header."
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
def operational_metrics(
    request: Request,
    response: Response,
) -> dict[str, Any]:
    """Return protected, low-cardinality metrics."""

    response.headers[
        "Cache-Control"
    ] = "no-store"

    metrics: OperationalMetrics = (
        request.app.state.operational_metrics
    )

    return {
        "status": "ok",
        "service": "ai-soc-copilot",
        "version": request.app.version,
        **metrics.snapshot(),
    }
