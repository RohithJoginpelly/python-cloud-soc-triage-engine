"""Secure runtime configuration validation tests."""

from __future__ import annotations

import pytest

from src.api.configuration import (
    ConfigurationValidationError,
    normalize_deployment_mode,
    require_valid_configuration,
    validate_runtime_configuration,
)


STRONG_API_KEY = (
    "API-2026-"
    "f8c7a6e5d4b3c2a19087654321"
)

STRONG_SESSION_SECRET = (
    "SESSION-2026-"
    "A1b2C3d4E5f6G7h8I9j0"
    "K1l2M3n4O5p6Q7r8"
)


def production_report(
    **overrides,
):
    """Build a valid production configuration."""

    values = {
        "deployment_mode": "production",
        "api_key": STRONG_API_KEY,
        "session_secret": (
            STRONG_SESSION_SECRET
        ),
        "session_secret_is_explicit": True,
        "session_https_only": True,
        "hsts_enabled": True,
        "log_format": "json",
    }

    values.update(overrides)

    return validate_runtime_configuration(
        **values
    )


def issue_codes(report):
    """Return configuration issue codes."""

    return {
        issue.code
        for issue in report.issues
    }


def test_deployment_mode_aliases_are_supported():
    assert normalize_deployment_mode(
        "dev"
    ) == "development"

    assert normalize_deployment_mode(
        "test"
    ) == "testing"

    assert normalize_deployment_mode(
        "prod"
    ) == "production"


def test_invalid_deployment_mode_is_rejected():
    with pytest.raises(
        ValueError,
        match="SOC_DEPLOYMENT_MODE",
    ):
        normalize_deployment_mode(
            "enterprise"
        )


def test_valid_production_configuration_passes():
    report = production_report()

    assert report.valid is True
    assert report.errors == ()
    assert report.warnings == ()


def test_missing_production_secrets_are_rejected():
    report = production_report(
        api_key=None,
        session_secret=None,
        session_secret_is_explicit=False,
    )

    codes = issue_codes(report)

    assert "api_key_missing" in codes
    assert "session_secret_missing" in codes
    assert (
        "session_secret_not_explicit"
        in codes
    )

    assert report.valid is False


def test_weak_and_placeholder_secrets_are_rejected():
    report = production_report(
        api_key="change-me",
        session_secret="A" * 64,
    )

    codes = issue_codes(report)

    assert "api_key_placeholder" in codes
    assert "session_secret_weak" in codes


def test_secret_reuse_is_rejected_in_production():
    shared_secret = (
        "Shared-Secret-2026-"
        "A1b2C3d4E5f6G7h8I9j0"
        "K1l2M3n4O5p6"
    )

    report = production_report(
        api_key=shared_secret,
        session_secret=shared_secret,
    )

    assert "secret_reuse" in (
        issue_codes(report)
    )

    assert report.valid is False


def test_insecure_production_transport_is_rejected():
    report = production_report(
        session_https_only=False,
        hsts_enabled=False,
    )

    codes = issue_codes(report)

    assert (
        "secure_cookie_disabled"
        in codes
    )
    assert "hsts_disabled" in codes
    assert report.valid is False


def test_text_logging_is_a_production_warning():
    report = production_report(
        log_format="text"
    )

    assert report.valid is True

    assert (
        "structured_logging_disabled"
        in issue_codes(report)
    )


def test_development_mode_allows_missing_secrets():
    report = validate_runtime_configuration(
        deployment_mode="development",
        api_key=None,
        session_secret=None,
        session_secret_is_explicit=False,
        session_https_only=False,
        hsts_enabled=False,
        log_format="text",
    )

    assert report.valid is True

    assert (
        "api_key_not_configured"
        in issue_codes(report)
    )


def test_safe_report_never_contains_secret_values():
    report = production_report()

    serialized = str(
        report.to_safe_dict()
    )

    assert STRONG_API_KEY not in serialized
    assert (
        STRONG_SESSION_SECRET
        not in serialized
    )


def test_require_valid_configuration_raises_safely():
    report = production_report(
        api_key="change-me",
    )

    with pytest.raises(
        ConfigurationValidationError,
    ) as captured:
        require_valid_configuration(
            report
        )

    message = str(captured.value)

    assert "api_key_placeholder" in message
    assert "change-me" not in message
