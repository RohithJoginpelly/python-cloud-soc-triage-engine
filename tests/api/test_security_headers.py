"""HTTP response security-header tests."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from src.api.app import create_app


PROJECT_ROOT = Path(
    __file__
).resolve().parents[2]

INPUT_ROOT = (
    PROJECT_ROOT
    / "data"
    / "test_events"
)


def build_app(tmp_path):
    """Create an isolated API application."""

    return create_app(
        database_path=tmp_path / "cases.db",
        input_root=INPUT_ROOT,
        api_key="security-header-api-key",
        session_secret=(
            "security-header-session-secret"
        ),
    )


def test_dashboard_has_security_headers(
    tmp_path,
    monkeypatch,
):
    """Dashboard responses include baseline headers."""

    monkeypatch.delenv(
        "SOC_ENABLE_HSTS",
        raising=False,
    )

    app = build_app(tmp_path)
    client = TestClient(app)

    response = client.get(
        "/dashboard/login"
    )

    assert response.status_code == 200

    assert response.headers[
        "x-frame-options"
    ] == "DENY"

    assert response.headers[
        "x-content-type-options"
    ] == "nosniff"

    assert response.headers[
        "referrer-policy"
    ] == "no-referrer"

    assert response.headers[
        "permissions-policy"
    ] == (
        "camera=(), microphone=(), "
        "geolocation=(), payment=(), "
        "usb=()"
    )

    assert (
        "strict-transport-security"
        not in response.headers
    )


def test_content_security_policy_is_present(
    tmp_path,
    monkeypatch,
):
    """Dashboard responses include the baseline CSP."""

    monkeypatch.delenv(
        "SOC_ENABLE_HSTS",
        raising=False,
    )

    app = build_app(tmp_path)
    client = TestClient(app)

    response = client.get(
        "/dashboard/login"
    )

    policy = response.headers[
        "content-security-policy"
    ]

    assert "default-src 'self'" in policy
    assert "base-uri 'self'" in policy
    assert "form-action 'self'" in policy
    assert "frame-ancestors 'none'" in policy
    assert "object-src 'none'" in policy
    assert "img-src 'self' data:" in policy
    assert "connect-src 'self'" in policy


def test_hsts_is_added_to_https_responses(
    tmp_path,
    monkeypatch,
):
    """Configured HTTPS responses include HSTS."""

    monkeypatch.setenv(
        "SOC_ENABLE_HSTS",
        "true",
    )

    app = build_app(tmp_path)

    client = TestClient(
        app,
        base_url="https://testserver",
    )

    response = client.get(
        "/dashboard/login"
    )

    assert response.status_code == 200

    assert response.headers[
        "strict-transport-security"
    ] == (
        "max-age=31536000; "
        "includeSubDomains"
    )


def test_hsts_is_not_sent_over_http(
    tmp_path,
    monkeypatch,
):
    """HSTS remains absent on insecure HTTP."""

    monkeypatch.setenv(
        "SOC_ENABLE_HSTS",
        "true",
    )

    app = build_app(tmp_path)

    client = TestClient(
        app,
        base_url="http://testserver",
    )

    response = client.get(
        "/dashboard/login"
    )

    assert response.status_code == 200

    assert (
        "strict-transport-security"
        not in response.headers
    )


def test_csp_disallows_inline_scripts_and_styles(
    tmp_path,
    monkeypatch,
):
    """CSP permits only same-origin scripts and styles."""

    monkeypatch.delenv(
        "SOC_ENABLE_HSTS",
        raising=False,
    )

    app = build_app(tmp_path)
    client = TestClient(app)

    response = client.get(
        "/dashboard/login"
    )

    assert response.status_code == 200

    policy = response.headers[
        "content-security-policy"
    ]

    assert "script-src 'self'" in policy
    assert "style-src 'self'" in policy
    assert "'unsafe-inline'" not in policy


def test_dashboard_loads_external_javascript(
    tmp_path,
    monkeypatch,
):
    """Dashboard uses the same-origin JavaScript file."""

    monkeypatch.delenv(
        "SOC_ENABLE_HSTS",
        raising=False,
    )

    app = build_app(tmp_path)
    client = TestClient(app)

    response = client.get(
        "/dashboard/login"
    )

    assert response.status_code == 200
    assert "/static/dashboard.js" in response.text
    assert "onchange=" not in response.text

    script_response = client.get(
        "/static/dashboard.js"
    )

    assert script_response.status_code == 200
    content_type = script_response.headers[
        "content-type"
    ].lower()

    assert "javascript" in content_type
    assert "data-auto-submit" in (
        script_response.text
    )
