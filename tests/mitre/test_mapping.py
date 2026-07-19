import pytest

from src.mitre.mapping import (
    map_finding_to_mitre,
    map_findings_to_mitre,
)


def build_finding(
    *,
    rule_id: str = "CORR-XDR-001",
    tags=None,
) -> dict:
    return {
        "correlation_id": "corr-test-001",
        "rule_id": rule_id,
        "tags": (
            tags
            if tags is not None
            else [
                "network_reconnaissance",
                "credential_access",
                "possible_account_compromise",
            ]
        ),
    }


def test_cross_source_rule_maps_three_techniques():
    mapping = map_finding_to_mitre(
        build_finding()
    )

    technique_ids = [
        technique.technique_id
        for technique in mapping.techniques
    ]

    assert technique_ids == [
        "T1078",
        "T1110.001",
        "T1595",
    ]


def test_rule_mappings_have_high_confidence():
    mapping = map_finding_to_mitre(
        build_finding()
    )

    assert all(
        technique.confidence == "high"
        for technique in mapping.techniques
    )


def test_authentication_rule_maps_two_techniques():
    mapping = map_finding_to_mitre(
        build_finding(
            rule_id="CORR-AUTH-001",
            tags=[],
        )
    )

    technique_ids = [
        technique.technique_id
        for technique in mapping.techniques
    ]

    assert technique_ids == [
        "T1078",
        "T1110.001",
    ]


def test_tag_fallback_mapping():
    mapping = map_finding_to_mitre(
        build_finding(
            rule_id="UNKNOWN-RULE",
            tags=[
                "network_reconnaissance",
            ],
        )
    )

    assert len(mapping.techniques) == 1
    assert (
        mapping.techniques[0].technique_id
        == "T1595"
    )
    assert (
        mapping.techniques[0].confidence
        == "medium"
    )


def test_rule_and_tag_mapping_are_deduplicated():
    mapping = map_finding_to_mitre(
        build_finding()
    )

    technique_ids = [
        technique.technique_id
        for technique in mapping.techniques
    ]

    assert len(technique_ids) == len(
        set(technique_ids)
    )
    assert len(technique_ids) == 3


def test_unknown_finding_returns_empty_mapping():
    mapping = map_finding_to_mitre(
        build_finding(
            rule_id="UNKNOWN-RULE",
            tags=["unmapped_tag"],
        )
    )

    assert mapping.techniques == []


def test_missing_correlation_id_is_rejected():
    finding = build_finding()
    del finding["correlation_id"]

    with pytest.raises(
        ValueError,
        match="correlation_id is required",
    ):
        map_finding_to_mitre(finding)


def test_invalid_finding_type_is_rejected():
    with pytest.raises(
        TypeError,
        match="CorrelationFinding or dictionary",
    ):
        map_finding_to_mitre(
            "invalid"
        )  # type: ignore[arg-type]


def test_multiple_findings_are_mapped():
    mappings = map_findings_to_mitre(
        [
            build_finding(),
            build_finding(
                rule_id="CORR-AUTH-001",
                tags=[],
            ),
        ]
    )

    assert len(mappings) == 2
    assert len(mappings[0].techniques) == 3
    assert len(mappings[1].techniques) == 2


def test_collection_must_be_a_list():
    with pytest.raises(
        TypeError,
        match="must be provided as a list",
    ):
        map_findings_to_mitre(
            {}
        )  # type: ignore[arg-type]
