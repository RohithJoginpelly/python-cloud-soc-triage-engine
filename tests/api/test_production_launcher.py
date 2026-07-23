"""Tests for the hardened production launcher."""

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_production_launcher_uses_container_hardening():
    script = (
        PROJECT_ROOT
        / "deploy"
        / "run-production-container.sh"
    ).read_text(encoding="utf-8")

    assert "--read-only" in script
    assert "--cap-drop ALL" in script
    assert "no-new-privileges:true" in script
    assert "--pids-limit 256" in script
    assert "--memory 768m" in script
    assert "--cpus 1.0" in script
    assert "--tmpfs" in script


def test_production_launcher_uses_persistent_storage():
    script = (
        PROJECT_ROOT
        / "deploy"
        / "run-production-container.sh"
    ).read_text(encoding="utf-8")

    assert "/app/data/cases" in script
    assert "/app/data/test_events,readonly" in script
    assert "--env-file" in script


def test_production_launcher_is_not_publicly_exposed():
    script = (
        PROJECT_ROOT
        / "deploy"
        / "run-production-container.sh"
    ).read_text(encoding="utf-8")

    assert "127.0.0.1:${HOST_PORT}:8000" in script
    assert "0.0.0.0:${HOST_PORT}:8000" not in script


def test_production_environment_template_has_no_secret():
    template = (
        PROJECT_ROOT / ".env.production.example"
    ).read_text(encoding="utf-8")

    assert "SOC_API_KEY=" in template
    assert "SOC_SESSION_SECRET=" in template
    assert "SOC_DEPLOYMENT_MODE=production" in template
    assert "SOC_SESSION_HTTPS_ONLY=true" in template
    assert "SOC_ENABLE_HSTS=true" in template
