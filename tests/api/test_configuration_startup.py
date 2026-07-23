"""Runtime configuration startup enforcement tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.api.app import create_app
from src.api.configuration import (
    ConfigurationValidationError,
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


def configure_production(
    monkeypatch,
) -> None:
    """Configure required production transport settings."""

    monkeypatch.setenv(
        "SOC_DEPLOYMENT_MODE",
        "production",
    )
    monkeypatch.setenv(
        "SOC_SESSION_HTTPS_ONLY",
        "true",
    )
    monkeypatch.setenv(
        "SOC_ENABLE_HSTS",
        "true",
    )
    monkeypatch.setenv(
        "SOC_LOG_FORMAT",
        "text",
    )


def build_paths(
    tmp_path: Path,
) -> tuple[Path, Path]:
    """Create isolated database and telemetry paths."""

    input_root = tmp_path / "telemetry"
    input_root.mkdir()

    return (
        tmp_path / "cases.db",
        input_root,
    )


def test_development_startup_remains_compatible(
    tmp_path,
    monkeypatch,
):
    monkeypatch.delenv(
        "SOC_DEPLOYMENT_MODE",
        raising=False,
    )
    monkeypatch.delenv(
        "SOC_SESSION_SECRET",
        raising=False,
    )

    database_path, input_root = (
        build_paths(tmp_path)
    )

    app = create_app(
        database_path=database_path,
        input_root=input_root,
        api_key="development-key",
        session_secret=(
            "development-session-secret"
        ),
    )

    assert app.state.deployment_mode == (
        "development"
    )

    report = (
        app.state.configuration_report
    )

    assert report.valid is True

    warning_codes = {
        issue.code
        for issue in report.warnings
    }

    assert "api_key_weak" in warning_codes
    assert (
        "session_secret_weak"
        in warning_codes
    )


def test_valid_production_configuration_starts(
    tmp_path,
    monkeypatch,
):
    configure_production(monkeypatch)

    database_path, input_root = (
        build_paths(tmp_path)
    )

    app = create_app(
        database_path=database_path,
        input_root=input_root,
        api_key=STRONG_API_KEY,
        session_secret=(
            STRONG_SESSION_SECRET
        ),
    )

    assert app.state.deployment_mode == (
        "production"
    )

    report = (
        app.state.configuration_report
    )

    assert report.valid is True

    warning_codes = {
        issue.code
        for issue in report.warnings
    }

    assert (
        "structured_logging_disabled"
        in warning_codes
    )


def test_production_requires_api_key(
    tmp_path,
    monkeypatch,
):
    configure_production(monkeypatch)

    database_path, input_root = (
        build_paths(tmp_path)
    )

    with pytest.raises(
        ConfigurationValidationError,
    ) as captured:
        create_app(
            database_path=database_path,
            input_root=input_root,
            api_key=None,
            session_secret=(
                STRONG_SESSION_SECRET
            ),
        )

    assert "api_key_missing" in str(
        captured.value
    )


def test_production_requires_explicit_session_secret(
    tmp_path,
    monkeypatch,
):
    configure_production(monkeypatch)

    monkeypatch.delenv(
        "SOC_SESSION_SECRET",
        raising=False,
    )

    database_path, input_root = (
        build_paths(tmp_path)
    )

    with pytest.raises(
        ConfigurationValidationError,
    ) as captured:
        create_app(
            database_path=database_path,
            input_root=input_root,
            api_key=STRONG_API_KEY,
        )

    message = str(captured.value)

    assert "session_secret_missing" in (
        message
    )
    assert (
        "session_secret_not_explicit"
        in message
    )
    assert STRONG_API_KEY not in message


def test_production_rejects_insecure_cookies(
    tmp_path,
    monkeypatch,
):
    configure_production(monkeypatch)

    monkeypatch.setenv(
        "SOC_SESSION_HTTPS_ONLY",
        "false",
    )

    database_path, input_root = (
        build_paths(tmp_path)
    )

    with pytest.raises(
        ConfigurationValidationError,
    ) as captured:
        create_app(
            database_path=database_path,
            input_root=input_root,
            api_key=STRONG_API_KEY,
            session_secret=(
                STRONG_SESSION_SECRET
            ),
        )

    assert "secure_cookie_disabled" in str(
        captured.value
    )


def test_production_rejects_disabled_hsts(
    tmp_path,
    monkeypatch,
):
    configure_production(monkeypatch)

    monkeypatch.setenv(
        "SOC_ENABLE_HSTS",
        "false",
    )

    database_path, input_root = (
        build_paths(tmp_path)
    )

    with pytest.raises(
        ConfigurationValidationError,
    ) as captured:
        create_app(
            database_path=database_path,
            input_root=input_root,
            api_key=STRONG_API_KEY,
            session_secret=(
                STRONG_SESSION_SECRET
            ),
        )

    assert "hsts_disabled" in str(
        captured.value
    )


def test_startup_failure_never_exposes_secrets(
    tmp_path,
    monkeypatch,
):
    configure_production(monkeypatch)

    secret_value = "change-me"

    database_path, input_root = (
        build_paths(tmp_path)
    )

    with pytest.raises(
        ConfigurationValidationError,
    ) as captured:
        create_app(
            database_path=database_path,
            input_root=input_root,
            api_key=secret_value,
            session_secret=secret_value,
        )

    message = str(captured.value)

    assert secret_value not in message
    assert "api_key_placeholder" in message
    assert (
        "session_secret_placeholder"
        in message
    )
