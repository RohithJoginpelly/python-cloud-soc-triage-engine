from types import SimpleNamespace

import pytest

from src.copilot.prompting import build_copilot_prompt
from src.copilot.providers.fallback import (
    FallbackCopilotProvider,
)
from src.copilot.providers.openai_provider import (
    OpenAICopilotProvider,
    OpenAIDraftSchema,
)


def build_packet() -> dict:
    return {
        "case_id": "case-test-001",
        "correlation_id": "corr-test-001",
        "title": "Possible SSH compromise",
        "summary": (
            "SSH reconnaissance was followed by failed "
            "and successful authentication activity."
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
            "event-3",
        ],
        "first_seen": "2026-07-18T16:18:00+00:00",
        "last_seen": "2026-07-18T16:28:00+00:00",
        "source_ip": "192.168.119.131",
        "username": "admin",
        "destination_host": "ubuntu-server",
        "mitre_techniques": [
            {
                "technique_id": "T1078",
                "name": "Valid Accounts",
            },
            {
                "technique_id": "T1110.001",
                "name": "Password Guessing",
            },
        ],
        "recommended_action": (
            "Validate the successful login."
        ),
    }


def build_openai_schema() -> OpenAIDraftSchema:
    return OpenAIDraftSchema(
        executive_summary=(
            "Suspicious SSH activity requires review."
        ),
        assessment=(
            "The sequence may represent unauthorized access."
        ),
        key_observations=[
            "Authentication activity was observed."
        ],
        investigation_steps=[
            "Validate the successful login."
        ],
        containment_considerations=[
            "Consider restricting the source IP."
        ],
        cited_event_ids=[
            "event-1",
            "event-2",
            "event-3",
        ],
        cited_mitre_techniques=[
            "T1078",
            "T1110.001",
        ],
        uncertainties=[
            "Authorization has not been confirmed."
        ],
    )


def test_fallback_provider_generates_draft():
    packet = build_packet()
    prompt = build_copilot_prompt(packet)

    result = FallbackCopilotProvider().generate(
        prompt,
        packet,
    )

    assert result.provider == "fallback"
    assert result.model == "deterministic-v1"

    assert result.draft.cited_event_ids == [
        "event-1",
        "event-2",
        "event-3",
    ]

    assert result.draft.cited_mitre_techniques == [
        "T1078",
        "T1110.001",
    ]


def test_fallback_requires_evidence_ids():
    packet = build_packet()
    packet["event_ids"] = []

    prompt = build_copilot_prompt(packet)

    with pytest.raises(
        ValueError,
        match="requires evidence event IDs",
    ):
        FallbackCopilotProvider().generate(
            prompt,
            packet,
        )


def test_openai_provider_uses_structured_output():
    captured = {}

    class FakeResponses:
        def parse(self, **kwargs):
            captured.update(kwargs)

            return SimpleNamespace(
                output_parsed=build_openai_schema(),
                _request_id="req-test-001",
            )

    fake_client = SimpleNamespace(
        responses=FakeResponses()
    )

    provider = OpenAICopilotProvider(
        model="test-model",
        client=fake_client,
    )

    packet = build_packet()
    prompt = build_copilot_prompt(packet)

    result = provider.generate(
        prompt,
        packet,
    )

    assert captured["model"] == "test-model"
    assert captured["input"] == prompt.text
    assert captured["store"] is False

    assert (
        captured["text_format"]
        is OpenAIDraftSchema
    )

    assert result.provider == "openai"
    assert result.model == "test-model"
    assert result.request_id == "req-test-001"


def test_openai_provider_rejects_empty_output():
    class FakeResponses:
        def parse(self, **kwargs):
            return SimpleNamespace(
                output_parsed=None,
                _request_id="req-empty",
            )

    fake_client = SimpleNamespace(
        responses=FakeResponses()
    )

    provider = OpenAICopilotProvider(
        model="test-model",
        client=fake_client,
    )

    packet = build_packet()
    prompt = build_copilot_prompt(packet)

    with pytest.raises(
        RuntimeError,
        match="no parsed Copilot draft",
    ):
        provider.generate(
            prompt,
            packet,
        )


def test_openai_provider_requires_api_key(
    monkeypatch,
):
    monkeypatch.delenv(
        "OPENAI_API_KEY",
        raising=False,
    )

    with pytest.raises(
        RuntimeError,
        match="OPENAI_API_KEY is required",
    ):
        OpenAICopilotProvider(
            model="test-model"
        )
