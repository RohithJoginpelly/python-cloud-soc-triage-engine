"""Tests for hardened production deployment files."""

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_production_requirements_exclude_legacy_packages():
    requirements = (
        PROJECT_ROOT / "requirements-production.txt"
    ).read_text(encoding="utf-8").lower()

    assert "fastapi==" in requirements
    assert "uvicorn==" in requirements
    assert "openai==" in requirements
    assert "boto3==" in requirements

    assert "streamlit" not in requirements
    assert "pandas" not in requirements
    assert "altair" not in requirements
    assert "pydeck" not in requirements
    assert "pytest" not in requirements
    assert "httpx2" not in requirements


def test_dockerfile_runs_v2_api_as_non_root():
    dockerfile = (
        PROJECT_ROOT / "Dockerfile"
    ).read_text(encoding="utf-8")

    assert "src.api.main:app" in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "EXPOSE 8000" in dockerfile
    assert "/health/live" in dockerfile
    assert "--workers\", \"1" in dockerfile

    assert "streamlit run" not in dockerfile
    assert "dashboard/app.py" not in dockerfile
    assert "EXPOSE 8501" not in dockerfile


def test_dockerfile_enables_production_safety_defaults():
    dockerfile = (
        PROJECT_ROOT / "Dockerfile"
    ).read_text(encoding="utf-8")

    assert "SOC_DEPLOYMENT_MODE=production" in dockerfile
    assert "SOC_SESSION_HTTPS_ONLY=true" in dockerfile
    assert "SOC_ENABLE_HSTS=true" in dockerfile
    assert "SOC_LOG_FORMAT=json" in dockerfile


def test_docker_context_excludes_sensitive_runtime_files():
    ignored = (
        PROJECT_ROOT / ".dockerignore"
    ).read_text(encoding="utf-8")

    assert ".env" in ignored
    assert "*.db" in ignored
    assert "*.db-*" in ignored
    assert "venv/" in ignored
    assert ".git/" in ignored
