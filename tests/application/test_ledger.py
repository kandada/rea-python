from rea_mcp.application.investigation import EvidenceLedger
from rea_mcp.domain.analysis_profile import ProviderIdentity, create_analysis_profile
from rea_mcp.domain.binary_target import BinaryTarget
from rea_mcp.domain.evidence import EvidenceObservation, create_evidence

PROVIDER = ProviderIdentity(id="fixture", name="Fixture", version="1")
TARGET = BinaryTarget(path="/tmp/x", sha256="a" * 64, format="elf", architecture="x86_64")
PROFILE = create_analysis_profile(PROVIDER, {})


def _evidence(result: object):  # type: ignore[no-untyped-def]
    return create_evidence(
        TARGET, PROVIDER, EvidenceObservation("inspect", result, analysis_profile=PROFILE)
    )


def test_record_is_idempotent() -> None:
    ledger = EvidenceLedger()
    evidence = _evidence({"a": 1})
    assert ledger.record(evidence).ok
    assert ledger.record(evidence).value == "duplicate"
    assert ledger.record_count == 1


def test_conflicting_record_is_rejected() -> None:
    ledger = EvidenceLedger()
    first = _evidence({"a": 1})
    ledger.record(first)
    # Same semantic id but different content is impossible to forge through the
    # public API; simulate by mutating a copy directly.
    forged = first.model_copy(update={"normalized_result": {"a": 2}})
    assert not ledger.record(forged).ok


def test_export_import_round_trip() -> None:
    ledger = EvidenceLedger()
    ledger.record(_evidence({"a": 1}))
    ledger.record(_evidence({"a": 2}))
    bundle = ledger.export_bundle()

    other = EvidenceLedger()
    delta = other.import_bundle(bundle.model_dump())
    assert delta.ok
    assert delta.value.records_added == 2
    assert other.record_count == 2

    again = other.import_bundle(bundle.model_dump())
    assert again.ok
    assert again.value.records_added == 0


def test_import_rejects_tampered_bundle() -> None:
    ledger = EvidenceLedger()
    ledger.record(_evidence({"a": 1}))
    bundle = ledger.export_bundle().model_dump()
    bundle["records"][0]["normalized_result"] = {"tampered": True}
    assert not EvidenceLedger().import_bundle(bundle).ok
