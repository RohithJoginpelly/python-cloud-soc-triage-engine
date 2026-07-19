import pytest

from src.copilot.validation import (
    validate_copilot_draft,
)


def build_packet() -> dict:
    return {
        "case_id": "case-test-001",
        "event_ids": [
            "event-1",
            "event-2",
            "event-3",
        ],
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
    }


def build_draft() -> dict:
    return {
        "executive_summary": (
            "Suspicious SSH activity requires review."
        ),
        "assessment": (
            "The activity may represent unauthorized access."
        ),
        "key_observations": [
            "Repeated login activity was observed."
        ],
        "investigation_steps": [
            "Validate whether the login was authorized."
        ],
        "containment_considerations": [
            "Consider restricting the source IP."
        ],
        "cited_event_ids": [
            "event-1",
            "event-2",
            "event-3",
        ],
        "cited_mitre_techniques": [
            "T1078",
            "T1110.001",
        ],
        "uncertainties": [
            "Authorization has not been confirmed."
        ],
    }


def test_valid_draft_passes():
    result = validate_copilot_draft(
        build_packet(),
        build_draft(),
    )

    assert result.valid is True
    assert result.errors == []
    assert result.warnings == []


def test_invented_event_id_is_rejected():
    draft = build_draft()
    draft["cited_event_ids"].append(
        "invented-event"
    )

    result = validate_copilot_draft(
        build_packet(),
        draft,
    )

    assert result.valid is False
    assert "invented-event" in result.errors[0]


def test_missing_event_citations_is_rejected():
    draft = build_draft()
    draft["cited_event_ids"] = []

    result = validate_copilot_draft(
        build_packet(),
        draft,
    )

    assert result.valid is False
    assert any(
        "at least one supporting event ID"
        in error
        for error in result.errors
    )


def test_invented_mitre_technique_is_rejected():
    draft = build_draft()
    draft["cited_mitre_techniques"].append(
        "T9999"
    )

    result = validate_copilot_draft(
        build_packet(),
        draft,
    )

    assert result.valid is False
    assert any(
        "T9999" in error
        for error in result.errors
    )


def test_partial_event_citation_creates_warning():
    draft = build_draft()
    draft["cited_event_ids"] = [
        "event-1",
    ]

    result = validate_copilot_draft(
        build_packet(),
        draft,
    )

    assert result.valid is True
    assert len(result.warnings) == 1


def test_missing_mitre_citations_creates_warning():
    draft = build_draft()
    draft["cited_mitre_techniques"] = []

    result = validate_copilot_draft(
        build_packet(),
        draft,
    )

    assert result.valid is True
    assert any(
        "did not cite any techniques"
        in warning
        for warning in result.warnings
    )


def test_overconfident_language_creates_warning():
    draft = build_draft()
    draft["assessment"] = (
        "This is a confirmed breach."
    )

    result = validate_copilot_draft(
        build_packet(),
        draft,
    )

    assert result.valid is True
    assert any(
        "overconfident language"
        in warning
        for warning in result.warnings
    )


def test_invalid_draft_structure_is_rejected():
    draft = build_draft()
    del draft["assessment"]

    with pytest.raises(
        ValueError,
        match="required output structure",
    ):
        validate_copilot_draft(
            build_packet(),
            draft,
        )


def test_invalid_packet_type_is_rejected():
    with pytest.raises(
        TypeError,
        match="AnalystTriagePacket or dictionary",
    ):
        validate_copilot_draft(
            "invalid",  # type: ignore[arg-type]
            build_draft(),
        )
