from rea_mcp.domain.analysis_profile import ProviderIdentity, create_analysis_profile
from rea_mcp.domain.binary_target import BinaryTarget
from rea_mcp.domain.evidence import (
    EvidenceObservation,
    compute_evidence_id,
    create_evidence,
    parse_evidence,
)
from rea_mcp.domain.evidence_bundle import create_evidence_bundle, parse_evidence_bundle

PROVIDER = ProviderIdentity(id="fixture", name="Fixture", version="1")
TARGET = BinaryTarget(path="/tmp/x", sha256="a" * 64, format="elf", architecture="x86_64")
PROFILE = create_analysis_profile(PROVIDER, {"loader": "default"})


def _evidence() -> object:
    return create_evidence(
        TARGET,
        PROVIDER,
        EvidenceObservation("inspect", {"sections": []}, analysis_profile=PROFILE),
    )


def test_evidence_round_trips() -> None:
    evidence = _evidence()
    parsed = parse_evidence(evidence.model_dump())
    assert parsed.ok
    assert parsed.value.evidence_id == evidence.evidence_id  # type: ignore[attr-defined]


def test_identity_ignores_display_path() -> None:
    evidence = _evidence()
    other = BinaryTarget(
        path="/different/name", sha256="a" * 64, format="elf", architecture="x86_64"
    )
    other_evidence = create_evidence(
        other, PROVIDER, EvidenceObservation("inspect", {"sections": []}, analysis_profile=PROFILE)
    )
    assert compute_evidence_id(evidence) == compute_evidence_id(other_evidence)  # type: ignore[arg-type]


def test_tampering_is_rejected() -> None:
    payload = _evidence().model_dump()  # type: ignore[attr-defined]
    payload["normalized_result"] = {"sections": ["tampered"]}
    assert not parse_evidence(payload).ok


def test_subject_absent_records_a_limitation() -> None:
    evidence = create_evidence(None, PROVIDER, EvidenceObservation("inspect", {"a": 1}))
    assert evidence.subject is None
    assert any("identity is unavailable" in item for item in evidence.limitations)


def test_bundle_round_trip_and_authentication() -> None:
    evidence = _evidence()
    bundle = create_evidence_bundle([evidence])  # type: ignore[list-item]
    assert parse_evidence_bundle(bundle.model_dump()).ok

    tampered = bundle.model_dump()
    tampered["records"][0]["normalized_result"] = {"changed": True}
    assert not parse_evidence_bundle(tampered).ok


def test_bundle_orders_records_by_id() -> None:
    a = _evidence()
    b = create_evidence(
        TARGET,
        PROVIDER,
        EvidenceObservation("inspect", {"sections": [1]}, analysis_profile=PROFILE),
    )
    bundle = create_evidence_bundle([b, a])  # type: ignore[list-item]
    ids = [record.evidence_id for record in bundle.records]
    assert ids == sorted(ids)
