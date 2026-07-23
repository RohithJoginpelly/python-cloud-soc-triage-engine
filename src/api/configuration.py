"""Secure runtime configuration validation."""

from __future__ import annotations

import logging

from dataclasses import dataclass
from typing import Literal


DeploymentMode = Literal[
    "development",
    "testing",
    "production",
]

IssueSeverity = Literal[
    "warning",
    "error",
]


CONFIGURATION_LOGGER = logging.getLogger(
    "soc.configuration"
)


PLACEHOLDER_SECRET_VALUES = {
    "change-me",
    "changeme",
    "replace-me",
    "replace-with-secure-value",
    "your-api-key",
    "your-secret",
    "example",
    "default",
    "password",
    "secret",
}


@dataclass(
    frozen=True,
    slots=True,
)
class ConfigurationIssue:
    """One safe configuration validation issue."""

    code: str
    severity: IssueSeverity
    message: str

    def to_dict(self) -> dict[str, str]:
        """Return a safe serialized issue."""

        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
        }


@dataclass(
    frozen=True,
    slots=True,
)
class ConfigurationReport:
    """Safe runtime configuration report."""

    deployment_mode: DeploymentMode
    issues: tuple[ConfigurationIssue, ...]

    @property
    def errors(
        self,
    ) -> tuple[ConfigurationIssue, ...]:
        """Return blocking configuration errors."""

        return tuple(
            issue
            for issue in self.issues
            if issue.severity == "error"
        )

    @property
    def warnings(
        self,
    ) -> tuple[ConfigurationIssue, ...]:
        """Return non-blocking configuration warnings."""

        return tuple(
            issue
            for issue in self.issues
            if issue.severity == "warning"
        )

    @property
    def valid(self) -> bool:
        """Return whether no blocking errors exist."""

        return not self.errors

    def to_safe_dict(
        self,
    ) -> dict[str, object]:
        """Return a report without secret values."""

        return {
            "deployment_mode": (
                self.deployment_mode
            ),
            "valid": self.valid,
            "error_count": len(self.errors),
            "warning_count": len(
                self.warnings
            ),
            "issues": [
                issue.to_dict()
                for issue in self.issues
            ],
        }


class ConfigurationValidationError(
    RuntimeError
):
    """Raised when production configuration is unsafe."""

    def __init__(
        self,
        report: ConfigurationReport,
    ) -> None:
        self.report = report

        error_codes = ", ".join(
            issue.code
            for issue in report.errors
        )

        super().__init__(
            "Unsafe runtime configuration: "
            + error_codes
        )


def normalize_deployment_mode(
    value: str | None,
) -> DeploymentMode:
    """Normalize and validate the deployment mode."""

    normalized = (
        value or "development"
    ).strip().lower()

    aliases = {
        "dev": "development",
        "test": "testing",
        "prod": "production",
    }

    normalized = aliases.get(
        normalized,
        normalized,
    )

    if normalized not in {
        "development",
        "testing",
        "production",
    }:
        raise ValueError(
            "SOC_DEPLOYMENT_MODE must be "
            "development, testing, or production."
        )

    return normalized  # type: ignore[return-value]


def _normalized_secret(
    value: str | None,
) -> str | None:
    """Normalize a configured secret."""

    if not isinstance(value, str):
        return None

    normalized = value.strip()

    return normalized or None


def _looks_like_placeholder(
    value: str,
) -> bool:
    """Detect common example or placeholder values."""

    normalized = value.strip().lower()

    if normalized in PLACEHOLDER_SECRET_VALUES:
        return True

    placeholder_fragments = (
        "change-me",
        "changeme",
        "replace-me",
        "your_api_key",
        "your-api-key",
        "your_secret",
        "your-secret",
        "example-key",
        "example-secret",
    )

    return any(
        fragment in normalized
        for fragment in placeholder_fragments
    )


def _has_low_character_diversity(
    value: str,
) -> bool:
    """Reject obviously repetitive secret values."""

    return len(set(value)) < 8


def _validate_secret(
    *,
    field_name: str,
    value: str | None,
    required: bool,
    minimum_length: int,
    missing_code: str,
    weak_code: str,
    placeholder_code: str,
    severity: IssueSeverity,
    issues: list[ConfigurationIssue],
) -> None:
    """Validate one secret without recording its value."""

    normalized = _normalized_secret(value)

    if normalized is None:
        if required:
            issues.append(
                ConfigurationIssue(
                    code=missing_code,
                    severity=severity,
                    message=(
                        f"{field_name} is required."
                    ),
                )
            )
        return

    if _looks_like_placeholder(normalized):
        issues.append(
            ConfigurationIssue(
                code=placeholder_code,
                severity=severity,
                message=(
                    f"{field_name} uses a known "
                    "placeholder value."
                ),
            )
        )
        return

    if (
        len(normalized) < minimum_length
        or _has_low_character_diversity(
            normalized
        )
    ):
        issues.append(
            ConfigurationIssue(
                code=weak_code,
                severity=severity,
                message=(
                    f"{field_name} does not meet "
                    "the required strength policy."
                ),
            )
        )


def validate_runtime_configuration(
    *,
    deployment_mode: str | None,
    api_key: str | None,
    session_secret: str | None,
    session_secret_is_explicit: bool,
    session_https_only: bool,
    hsts_enabled: bool,
    log_format: str,
) -> ConfigurationReport:
    """Validate security-sensitive runtime settings."""

    mode = normalize_deployment_mode(
        deployment_mode
    )

    issues: list[ConfigurationIssue] = []

    production = mode == "production"

    _validate_secret(
        field_name="SOC_API_KEY",
        value=api_key,
        required=production,
        minimum_length=32,
        missing_code="api_key_missing",
        weak_code="api_key_weak",
        placeholder_code=(
            "api_key_placeholder"
        ),
        severity=(
            "error"
            if production
            else "warning"
        ),
        issues=issues,
    )

    _validate_secret(
        field_name="SOC_SESSION_SECRET",
        value=session_secret,
        required=production,
        minimum_length=48,
        missing_code=(
            "session_secret_missing"
        ),
        weak_code="session_secret_weak",
        placeholder_code=(
            "session_secret_placeholder"
        ),
        severity=(
            "error"
            if production
            else "warning"
        ),
        issues=issues,
    )

    normalized_api_key = _normalized_secret(
        api_key
    )

    normalized_session_secret = (
        _normalized_secret(
            session_secret
        )
    )

    if (
        production
        and not session_secret_is_explicit
    ):
        issues.append(
            ConfigurationIssue(
                code=(
                    "session_secret_not_explicit"
                ),
                severity="error",
                message=(
                    "SOC_SESSION_SECRET must be "
                    "configured explicitly in "
                    "production."
                ),
            )
        )

    if (
        normalized_api_key
        and normalized_session_secret
        and normalized_api_key
        == normalized_session_secret
    ):
        issues.append(
            ConfigurationIssue(
                code="secret_reuse",
                severity=(
                    "error"
                    if production
                    else "warning"
                ),
                message=(
                    "The API key and session secret "
                    "must use different values."
                ),
            )
        )

    if production and not session_https_only:
        issues.append(
            ConfigurationIssue(
                code="secure_cookie_disabled",
                severity="error",
                message=(
                    "HTTPS-only session cookies are "
                    "required in production."
                ),
            )
        )

    if production and not hsts_enabled:
        issues.append(
            ConfigurationIssue(
                code="hsts_disabled",
                severity="error",
                message=(
                    "HTTP Strict Transport Security "
                    "is required in production."
                ),
            )
        )

    normalized_log_format = (
        log_format.strip().lower()
    )

    if (
        production
        and normalized_log_format != "json"
    ):
        issues.append(
            ConfigurationIssue(
                code="structured_logging_disabled",
                severity="warning",
                message=(
                    "JSON logging is recommended for "
                    "production deployments."
                ),
            )
        )

    if (
        not production
        and normalized_api_key is None
    ):
        issues.append(
            ConfigurationIssue(
                code="api_key_not_configured",
                severity="warning",
                message=(
                    "Protected API routes will remain "
                    "unavailable until an API key is "
                    "configured."
                ),
            )
        )

    return ConfigurationReport(
        deployment_mode=mode,
        issues=tuple(issues),
    )


def require_valid_configuration(
    report: ConfigurationReport,
) -> None:
    """Raise when blocking configuration errors exist."""

    if not report.valid:
        raise ConfigurationValidationError(
            report
        )



def log_configuration_report(
    report: ConfigurationReport,
) -> None:
    """Log a secret-free startup configuration summary."""

    if report.errors:
        level = logging.ERROR
        message = (
            "Runtime configuration validation failed"
        )
    elif report.warnings:
        level = logging.WARNING
        message = (
            "Runtime configuration validated "
            "with warnings"
        )
    else:
        level = logging.INFO
        message = (
            "Runtime configuration validated"
        )

    CONFIGURATION_LOGGER.log(
        level,
        message,
        extra={
            "event_type": (
                "runtime_configuration_validated"
            ),
            "deployment_mode": (
                report.deployment_mode
            ),
            "valid": report.valid,
            "error_count": len(
                report.errors
            ),
            "warning_count": len(
                report.warnings
            ),
            "issue_codes": [
                issue.code
                for issue in report.issues
            ],
        },
    )
