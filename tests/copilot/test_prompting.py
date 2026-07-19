import pytest

from src.copilot.prompting import (
    build_copilot_prompt,
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


def test_prompt_contains_case_context():
    prompt = build_copilot_prompt(
        build_packet()
    )

    assert prompt.case_id == "case-test-001"
    assert "event-1" in prompt.text
    assert "T1078" in prompt.text
    assert '"risk_score": 100' in prompt.text


def test_prompt_contains_safety_rules():
    prompt = build_copilot_prompt(
        build_packet()
    )

    assert "Do not invent events" in prompt.text
    assert "Return valid JSON only" in prompt.text
    assert "Do not change the supplied risk score" in (
        prompt.text
    )


def test_prompt_id_is_deterministic():
    first = build_copilot_prompt(
        build_packet()
    )

    second = build_copilot_prompt(
        build_packet()
    )

    assert first.prompt_id == second.prompt_id


def test_packet_dictionary_is_not_modified():
    packet = build_packet()

    build_copilot_prompt(packet)

    assert packet["event_ids"] == [
        "event-1",
        "event-2",
    ]


def test_missing_case_id_is_rejected():
    packet = build_packet()
    del packet["case_id"]

    with pytest.raises(
        ValueError,
        match="case_id is required",
    ):
        build_copilot_prompt(packet)


def test_invalid_packet_type_is_rejected():
    with pytest.raises(
        TypeError,
        match="AnalystTriagePacket or dictionary",
    ):
        build_copilot_prompt(
            "invalid"
        )  # type: ignore[arg-type]
