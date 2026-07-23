import pytest

from src.copilot.models import CopilotDraft
from src.copilot.providers.base import ProviderDraft
from src.copilot.service import (
    CopilotValidationError,
    create_copilot_provider,
    run_copilot,
)


def build_packet() -> dict:
    return {
        "case_id": "case-test-001",
        "correlation_id": "corr-test-001",
        "title": "Possible SSH compromise",
        "summary": (
            "SSH reconnaissance was followed by "
            "authentication activity."
        ),
        "severity": "critical",
        "confidence": 0.88,
        "risk_score": 100,
        "risk_level": "critical",
        "priority": "P1",
        "source_products": [
            "snort",
            "wazuh",
        ],
        "event_ids": [
            "event-1",
            "event-2",
        ],
        "first_seen": "2026-07-18T16:18:00+00:00",
        "last_seen": "2026-07-18T16:28:00+00:00",
        "mitre_techniques": [
            {
                "technique_id": "T1078",
                "name": "Valid Accounts",
            }
        ],
        "recommended_action": (
            "Validate the successful login."
        ),
    }


def test_fallback_service_run_is_valid():
    result = run_copilot(
        build_packet(),
        provider_name="fallback",
    )

    assert result.provider == "fallback"
    assert result.validation.valid is True
    assert result.case_id == "case-test-001"
    assert result.prompt_id.startswith("prompt-")


def test_default_provider_is_fallback(
    monkeypatch,
):
    monkeypatch.delenv(
        "COPILOT_PROVIDER",
        raising=False,
    )

    provider = create_copilot_provider()

    assert provider.name == "fallback"


def test_unknown_provider_is_rejected():
    with pytest.raises(
        ValueError,
        match="Unsupported Copilot provider",
    ):
        create_copilot_provider("unknown")


def test_invented_evidence_is_rejected():
    class UnsafeProvider:
        name = "unsafe"
        model = "unsafe-test"

        def generate(self, prompt, packet):
            draft = CopilotDraft(
                executive_summary=(
                    "Suspicious activity."
                ),
                assessment=(
                    "This activity requires review."
                ),
                key_observations=[
                    "A login occurred."
                ],
                investigation_steps=[
                    "Review the login."
                ],
                containment_considerations=[],
                cited_event_ids=[
                    "invented-event-id"
                ],
                cited_mitre_techniques=[
                    "T1078"
                ],
                uncertainties=[
                    "Authorization is unknown."
                ],
            )

            return ProviderDraft(
                provider=self.name,
                model=self.model,
                draft=draft,
            )

    with pytest.raises(
        CopilotValidationError,
        match="invented-event-id",
    ):
        run_copilot(
            build_packet(),
            provider=UnsafeProvider(),
        )


def test_run_result_can_be_serialized():
    result = run_copilot(
        build_packet(),
        provider_name="fallback",
    )

    serialized = result.to_dict()

    assert serialized["provider"] == "fallback"
    assert serialized["validation"]["valid"] is True

    assert serialized["draft"][
        "cited_event_ids"
    ] == [
        "event-1",
        "event-2",
    ]
