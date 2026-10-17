from rea_mcp.domain.reconstruction import Obligation, build_ledger, evaluate_coverage


def _ob(name: str, required: list[str], provided: list[str]) -> Obligation:
    return Obligation(name=name, required_facets=required, provided_facets=provided)


def test_build_and_evaluate() -> None:
    ledger = build_ledger(
        [
            _ob("f1", ["pseudocode", "types"], ["pseudocode", "types"]),
            _ob("f2", ["pseudocode", "types"], ["pseudocode"]),
            _ob("f3", ["pseudocode"], []),
        ]
    )
    assert ledger.covered == 1
    assert ledger.partial == 1
    assert ledger.open == 1
    assert ledger.coverage == round(1 / 3, 4)

    coverage = evaluate_coverage(ledger)
    assert coverage["complete"] is False
    assert {gap["name"] for gap in coverage["gaps"]} == {"f2", "f3"}


def test_complete_ledger() -> None:
    ledger = build_ledger([_ob("f1", ["pseudocode"], ["pseudocode"])])
    coverage = evaluate_coverage(ledger)
    assert coverage["complete"] is True
    assert coverage["coverage"] == 1.0


def test_obligation_without_required_facets_is_unknown() -> None:
    ledger = build_ledger([_ob("f1", [], [])])
    assert ledger.obligations[0].status == "unknown"
    assert ledger.limitations
