"""Reconstruction obligations, coverage and verification (pure domain).

Reconstruction is the "understand -> rebuild -> verify" half of an
investigation: given a set of obligations (things that must be reconstructed)
and the facets observed for each, this computes coverage and identifies gaps.
Facets are caller-supplied strings (e.g. pseudocode, assembly, types, behavior).
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ObligationStatus = Literal["covered", "partial", "open", "unknown"]


class Obligation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1)
    kind: str = Field(default="function")
    required_facets: list[str] = Field(default_factory=list)
    provided_facets: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)


class ObligationResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    kind: str
    status: ObligationStatus
    missing_facets: list[str]
    provided_facets: list[str]


class ReconstructionLedger(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    obligations: list[ObligationResult]
    covered: int
    partial: int
    open: int
    coverage: float
    limitations: list[str] = Field(default_factory=list)


def _classify(obligation: Obligation) -> ObligationResult:
    required = list(dict.fromkeys(obligation.required_facets))
    provided = set(obligation.provided_facets)
    if not required:
        status: ObligationStatus = "unknown"
        missing: list[str] = []
    else:
        missing = [facet for facet in required if facet not in provided]
        if not missing:
            status = "covered"
        elif len(missing) < len(required):
            status = "partial"
        else:
            status = "open"
    return ObligationResult(
        name=obligation.name,
        kind=obligation.kind,
        status=status,
        missing_facets=missing,
        provided_facets=sorted(provided),
    )


def build_ledger(obligations: list[Obligation]) -> ReconstructionLedger:
    results = [_classify(obligation) for obligation in obligations]
    covered = sum(1 for result in results if result.status == "covered")
    partial = sum(1 for result in results if result.status == "partial")
    open_count = sum(1 for result in results if result.status == "open")
    known = covered + partial + open_count
    coverage = (covered / known) if known else 0.0
    limitations: list[str] = []
    if any(result.status == "unknown" for result in results):
        limitations.append("Obligations without required facets are unknown, not covered.")
    return ReconstructionLedger(
        obligations=results,
        covered=covered,
        partial=partial,
        open=open_count,
        coverage=round(coverage, 4),
        limitations=limitations,
    )


def evaluate_coverage(ledger: ReconstructionLedger) -> dict[str, Any]:
    gaps = [
        {"name": result.name, "missing_facets": result.missing_facets}
        for result in ledger.obligations
        if result.status in ("partial", "open")
    ]
    return {
        "coverage": ledger.coverage,
        "covered": ledger.covered,
        "partial": ledger.partial,
        "open": ledger.open,
        "complete": ledger.partial == 0 and ledger.open == 0 and ledger.covered > 0,
        "gaps": gaps,
        "limitations": ledger.limitations,
    }


__all__ = [
    "Obligation",
    "ObligationResult",
    "ObligationStatus",
    "ReconstructionLedger",
    "build_ledger",
    "evaluate_coverage",
]
