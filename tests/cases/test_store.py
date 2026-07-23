import pytest

from src.cases.store import SQLiteCaseStore


def build_packet(
    *,
    case_id: str = "case-test-001",
    risk_score: int = 100,
) -> dict:
    return {
        "case_id": case_id,
        "correlation_id": "corr-test-001",
        "title": "Possible SSH compromise",
        "priority": "P1",
        "risk_score": risk_score,
        "risk_level": "critical",
        "event_ids": [
            "event-1",
            "event-2",
        ],
    }


def build_copilot_result() -> dict:
    return {
        "case_id": "case-test-001",
        "prompt_id": "prompt-test-001",
        "provider": "fallback",
        "model": "deterministic-v1",
        "draft": {
            "executive_summary": (
                "Suspicious SSH activity."
            )
        },
        "validation": {
            "valid": True,
            "errors": [],
            "warnings": [],
        },
    }


def test_save_packet_creates_case(tmp_path):
    store = SQLiteCaseStore(
        tmp_path / "cases.db"
    )

    case = store.save_packet(
        build_packet()
    )

    assert case.case_id == "case-test-001"
    assert case.status == "new"
    assert case.priority == "P1"
    assert case.risk_score == 100
    assert case.packet["event_ids"] == [
        "event-1",
        "event-2",
    ]


def test_saved_case_can_be_read(tmp_path):
    store = SQLiteCaseStore(
        tmp_path / "cases.db"
    )

    store.save_packet(
        build_packet()
    )

    case = store.get_case(
        "case-test-001"
    )

    assert case is not None
    assert case.correlation_id == (
        "corr-test-001"
    )


def test_packet_update_preserves_workflow_fields(
    tmp_path,
):
    store = SQLiteCaseStore(
        tmp_path / "cases.db"
    )

    store.save_packet(
        build_packet()
    )

    store.update_case(
        "case-test-001",
        status="investigating",
        assigned_to="alice@example.com",
    )

    updated_packet = build_packet(
        risk_score=95
    )

    case = store.save_packet(
        updated_packet
    )

    assert case.status == "investigating"
    assert case.assigned_to == (
        "alice@example.com"
    )
    assert case.risk_score == 95


def test_copilot_result_is_saved(tmp_path):
    store = SQLiteCaseStore(
        tmp_path / "cases.db"
    )

    store.save_packet(
        build_packet()
    )

    case = store.save_copilot_result(
        "case-test-001",
        build_copilot_result(),
    )

    assert case.copilot_result is not None
    assert case.copilot_result[
        "provider"
    ] == "fallback"


def test_case_status_and_assignment_are_updated(
    tmp_path,
):
    store = SQLiteCaseStore(
        tmp_path / "cases.db"
    )

    store.save_packet(
        build_packet()
    )

    case = store.update_case(
        "case-test-001",
        status="investigating",
        assigned_to="analyst@example.com",
        note="Reviewing evidence.",
        actor="analyst@example.com",
    )

    assert case.status == "investigating"
    assert case.assigned_to == (
        "analyst@example.com"
    )


def test_invalid_status_is_rejected(tmp_path):
    store = SQLiteCaseStore(
        tmp_path / "cases.db"
    )

    store.save_packet(
        build_packet()
    )

    with pytest.raises(
        ValueError,
        match="Unsupported case status",
    ):
        store.update_case(
            "case-test-001",
            status="unknown-state",
        )


def test_missing_case_is_rejected(tmp_path):
    store = SQLiteCaseStore(
        tmp_path / "cases.db"
    )

    with pytest.raises(
        KeyError,
        match="Case not found",
    ):
        store.update_case(
            "missing-case",
            status="triage",
        )


def test_cases_can_be_filtered_by_status(
    tmp_path,
):
    store = SQLiteCaseStore(
        tmp_path / "cases.db"
    )

    store.save_packet(
        build_packet(
            case_id="case-one"
        )
    )

    store.save_packet(
        {
            **build_packet(
                case_id="case-two"
            ),
            "correlation_id": "corr-test-002",
        }
    )

    store.update_case(
        "case-two",
        status="resolved",
    )

    new_cases = store.list_cases(
        status="new"
    )

    resolved_cases = store.list_cases(
        status="resolved"
    )

    assert [
        case.case_id
        for case in new_cases
    ] == ["case-one"]

    assert [
        case.case_id
        for case in resolved_cases
    ] == ["case-two"]


def test_audit_history_is_append_only(tmp_path):
    store = SQLiteCaseStore(
        tmp_path / "cases.db"
    )

    store.save_packet(
        build_packet()
    )

    store.save_copilot_result(
        "case-test-001",
        build_copilot_result(),
    )

    store.update_case(
        "case-test-001",
        status="investigating",
        actor="analyst@example.com",
    )

    events = store.get_audit_events(
        "case-test-001"
    )

    assert [
        event.event_type
        for event in events
    ] == [
        "case_created",
        "copilot_result_saved",
        "case_updated",
    ]

    assert [
        event.audit_id
        for event in events
    ] == sorted(
        event.audit_id
        for event in events
    )


def test_empty_update_is_rejected(tmp_path):
    store = SQLiteCaseStore(
        tmp_path / "cases.db"
    )

    store.save_packet(
        build_packet()
    )

    with pytest.raises(
        ValueError,
        match="At least one case update",
    ):
        store.update_case(
            "case-test-001"
        )
