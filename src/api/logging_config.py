"""Application logging configuration for the SOC platform."""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass
from typing import TextIO

from src.api.observability import (
    StructuredJSONFormatter,
)


SUPPORTED_LOG_FORMATS = {
    "text",
    "json",
}

SUPPORTED_LOG_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}

MANAGED_LOGGERS = (
    "soc.http",
    "soc.security",
    "soc.health",
    "soc.configuration",
    "src.api.error_handling",
)


@dataclass(frozen=True, slots=True)
class LoggingConfiguration:
    """Resolved application logging configuration."""

    log_format: str
    level_name: str
    level: int


def _remove_managed_handlers(
    logger: logging.Logger,
) -> None:
    """Remove handlers previously created here."""

    managed_handlers = [
        handler
        for handler in logger.handlers
        if getattr(
            handler,
            "_soc_structured_handler",
            False,
        )
    ]

    for handler in managed_handlers:
        logger.removeHandler(handler)


def configure_application_logging(
    *,
    log_format: str | None = None,
    level_name: str | None = None,
    stream: TextIO | None = None,
) -> LoggingConfiguration:
    """Configure readable or structured SOC logging."""

    resolved_format = (
        log_format
        if log_format is not None
        else os.getenv(
            "SOC_LOG_FORMAT",
            "text",
        )
    ).strip().lower()

    if resolved_format not in (
        SUPPORTED_LOG_FORMATS
    ):
        raise ValueError(
            "SOC_LOG_FORMAT must be "
            "'text' or 'json'."
        )

    resolved_level_name = (
        level_name
        if level_name is not None
        else os.getenv(
            "SOC_LOG_LEVEL",
            "INFO",
        )
    ).strip().upper()

    if resolved_level_name not in (
        SUPPORTED_LOG_LEVELS
    ):
        raise ValueError(
            "SOC_LOG_LEVEL must be one of: "
            "DEBUG, INFO, WARNING, ERROR, "
            "CRITICAL."
        )

    resolved_level = (
        SUPPORTED_LOG_LEVELS[
            resolved_level_name
        ]
    )

    for logger_name in MANAGED_LOGGERS:
        logger = logging.getLogger(
            logger_name
        )

        _remove_managed_handlers(
            logger
        )

        if resolved_format == "text":
            # Preserve pytest, Uvicorn, and local
            # development logging behavior.
            logger.propagate = True
            logger.setLevel(
                logging.NOTSET
            )
            continue

        handler = logging.StreamHandler(
            stream
            if stream is not None
            else sys.stderr
        )

        handler.setLevel(
            resolved_level
        )

        handler.setFormatter(
            StructuredJSONFormatter()
        )

        setattr(
            handler,
            "_soc_structured_handler",
            True,
        )

        logger.addHandler(handler)
        logger.setLevel(resolved_level)
        logger.propagate = False

    return LoggingConfiguration(
        log_format=resolved_format,
        level_name=resolved_level_name,
        level=resolved_level,
    )
