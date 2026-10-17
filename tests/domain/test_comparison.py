from rea_mcp.domain.analysis_profile import ProviderIdentity, create_analysis_profile
from rea_mcp.domain.binary_target import BinaryTarget
from rea_mcp.domain.comparison import compare_evidence
from rea_mcp.domain.coverage import RelationshipCoverage
from rea_mcp.domain.evidence import EvidenceObservation, create_evidence

PROVIDER = ProviderIdentity(id="fixture", name="Fixture", version="1")
TARGET = BinaryTarget(path="/tmp/x", sha256="a" * 64, format="elf", architecture="x86_64")
PROFILE = create_analysis_profile(PROVIDER, {})


def _make(result: object, coverage: RelationshipCoverage | None = None):  # type: ignore[no-untyped-def]
    return create_evidence(
        TARGET,
        PROVIDER,
        EvidenceObservation(
            "inspect", result, analysis_profile=PROFILE, relationship_coverage=coverage
        ),
    )


def test_identical_results_are_unchanged() -> None:
    left = _make({"a": 1})
    right = _make({"a": 1})
    assert compare_evidence(left, right).status == "unchanged"


def test_different_results_are_changed() -> None:
    result = compare_evidence(_make({"a": 1}), _make({"a": 2}))
    assert result.status == "changed"
    assert "normalized_result" in result.deltas


def test_partial_coverage_reports_truncated() -> None:
    coverage = RelationshipCoverage(status="partial")
    result = compare_evidence(_make({"a": 1}, coverage), _make({"a": 1}, coverage))
    assert result.status == "truncated"


def test_different_operations_are_unknown() -> None:
    left = _make({"a": 1})
    right = create_evidence(
        TARGET, PROVIDER, EvidenceObservation("other", {"a": 1}, analysis_profile=PROFILE)
    )
    assert compare_evidence(left, right).status == "unknown"
