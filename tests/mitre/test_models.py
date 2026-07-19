import pytest

from src.mitre.models import (
    MitreMapping,
    MitreTechnique,
)


def build_technique() -> MitreTechnique:
    return MitreTechnique(
        technique_id="T1110.001",
        name="Password Guessing",
        tactics=["Credential Access"],
        confidence="HIGH",
        evidence="Repeated failed logins were observed.",
    )


def test_technique_values_are_normalized():
    technique = build_technique()

    assert technique.technique_id == "T1110.001"
    assert technique.confidence == "high"
    assert technique.tactics == [
        "credential_access",
    ]


def test_duplicate_tactics_are_removed():
    technique = MitreTechnique(
        technique_id="T1078",
        name="Valid Accounts",
        tactics=[
            "Initial Access",
            "initial-access",
            "Persistence",
        ],
        confidence="high",
        evidence="A successful login was observed.",
    )

    assert technique.tactics == [
        "initial_access",
        "persistence",
    ]


def test_invalid_technique_id_is_rejected():
    with pytest.raises(
        ValueError,
        match="Invalid MITRE",
    ):
        MitreTechnique(
            technique_id="INVALID",
            name="Invalid",
            tactics=["credential_access"],
            confidence="high",
            evidence="Evidence.",
        )


def test_invalid_confidence_is_rejected():
    with pytest.raises(
        ValueError,
        match="Unsupported MITRE",
    ):
        MitreTechnique(
            technique_id="T1078",
            name="Valid Accounts",
            tactics=["initial_access"],
            confidence="certain",
            evidence="Evidence.",
        )


def test_mapping_id_is_deterministic():
    first = MitreMapping(
        correlation_id="corr-123",
        techniques=[build_technique()],
    )

    second = MitreMapping(
        correlation_id="corr-123",
        techniques=[build_technique()],
    )

    assert first.mapping_id == second.mapping_id


def test_mapping_can_be_serialized():
    mapping = MitreMapping(
        correlation_id="corr-123",
        techniques=[build_technique()],
    )

    result = mapping.to_dict()

    assert result["correlation_id"] == "corr-123"
    assert result["techniques"][0][
        "technique_id"
    ] == "T1110.001"
