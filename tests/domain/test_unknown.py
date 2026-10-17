from rea_mcp.domain.residual_unknown import (
    Probe,
    RecordUnknownInput,
    Resolution,
    create_residual_unknown,
    stable_unknown_id,
    update_residual_unknown,
)


def _record(**kwargs: object):
    base = {"question": "Is the parser reachable?", "domain": "reachability"}
    base.update(kwargs)
    return create_residual_unknown(RecordUnknownInput(**base), ["ev_" + "0" * 64])


def test_stable_id_normalizes_whitespace() -> None:
    assert stable_unknown_id("a  b", "d", None) == stable_unknown_id("a b", "d", None)


def test_create_sets_open_status_and_revision_one() -> None:
    unknown = _record()
    assert unknown.status == "open"
    assert unknown.revision == 1
    assert unknown.previous_revision_digest is None


def test_contradicting_evidence_marks_contradicted() -> None:
    unknown = _record(contradicting_evidence_ids=["ev_" + "1" * 64])
    assert unknown.status == "contradicted"


def test_update_requires_revision_and_resolution_consistency() -> None:
    unknown = _record()
    # Resolved without a resolution is rejected.
    bad = update_residual_unknown(unknown, status="resolved", mutation_evidence_id="ev_" + "2" * 64)
    assert not bad.ok

    good = update_residual_unknown(
        unknown,
        status="resolved",
        resolution=Resolution(
            disposition="verified", rationale="confirmed", evidence_ids=["ev_" + "3" * 64]
        ),
        mutation_evidence_id="ev_" + "2" * 64,
    )
    assert good.ok
    assert good.value.revision == 2
    assert good.value.previous_revision_digest == unknown.revision_digest


def test_recommended_probes_sorted_stable() -> None:
    unknown = _record(
        recommended_probes=[
            Probe(operation="b", rationale="x"),
            Probe(operation="a", rationale="y"),
        ]
    )
    assert [probe.operation for probe in unknown.recommended_probes] == ["b", "a"]
