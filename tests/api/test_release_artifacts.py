"""Release-artifact validation tests for v2.0.0."""

from __future__ import annotations

from pathlib import Path

from src.api.app import API_VERSION


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def read_text(relative_path: str) -> str:
    """Read one UTF-8 release artifact."""

    return (
        PROJECT_ROOT / relative_path
    ).read_text(encoding="utf-8")


def test_api_version_is_v2_release():
    assert API_VERSION == "2.0.0"


def test_readme_describes_current_test_total_and_dashboard():
    readme = read_text("README.md")

    assert "413 passed" in readme
    assert (
        "authenticated, role-based FastAPI dashboard"
        in readme
    )
    assert "## Version 2.0 Release" in readme


def test_demo_walkthrough_uses_verified_v2_workflow():
    walkthrough = read_text(
        "docs/demo_walkthrough.md"
    )

    assert "python -m src.v2_cli" in walkthrough
    assert (
        "sample_snort_ssh_recon.json"
        in walkthrough
    )
    assert (
        "sample_wazuh_ssh_compromise.json"
        in walkthrough
    )
    assert "python -m src.identity.cli" in walkthrough
    assert "src.api.main:app" in walkthrough
    assert "streamlit" not in walkthrough.lower()
    assert "8501" not in walkthrough


def test_release_notes_and_roadmap_status_exist():
    release_notes = read_text(
        "docs/RELEASE_NOTES_V2.md"
    )
    roadmap = read_text("docs/V2_ROADMAP.md")

    assert "AI SOC Copilot v2.0.0" in release_notes
    assert "413 automated tests" in release_notes
    assert "Release status:" in roadmap
    assert "`v2.0.0`" in roadmap


def test_runtime_incident_database_is_ignored():
    gitignore = read_text(".gitignore")

    assert "data/incidents/*.db" in gitignore
    assert "data/incidents/*.db-*" in gitignore
    assert (
        PROJECT_ROOT
        / "data"
        / "incidents"
        / ".gitkeep"
    ).is_file()
