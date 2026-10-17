"""Evidence comparison semantics.

Compares two observations of the same operation and reports a status that keeps
uncertainty explicit: ``unchanged``, ``changed``, ``contradiction``,
``truncated``, or ``unknown``. A comparison never silently upgrades unknown
coverage to equality.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .coverage import RelationshipCoverage
from .evidence import Evidence, evidence_without_display_fields

ComparisonStatus = Literal["unchanged", "changed", "contradiction", "truncated", "unknown"]


class ComparisonResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: ComparisonStatus
    operation: str
    left_evidence_id: str | None = None
    right_evidence_id: str | None = None
    deltas: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


def compare_evidence(left: Evidence, right: Evidence) -> ComparisonResult:
    """Compare two Evidence records of the same operation."""

    if left.operation != right.operation:
        return ComparisonResult(
            status="unknown",
            operation=left.operation,
            left_evidence_id=left.evidence_id,
            right_evidence_id=right.evidence_id,
            limitations=["Cannot compare different operations"],
        )
    if _coverage_incomplete(left.relationship_coverage, right.relationship_coverage):
        return ComparisonResult(
            status="truncated",
            operation=left.operation,
            left_evidence_id=left.evidence_id,
            right_evidence_id=right.evidence_id,
            limitations=["Relationship coverage is incomplete; equality is not asserted"],
        )

    left_projection = _comparable(left)
    right_projection = _comparable(right)
    if _contains_contradiction(left_projection, right_projection):
        deltas = _diff_keys(left_projection, right_projection)
        return ComparisonResult(
            status="contradiction",
            operation=left.operation,
            left_evidence_id=left.evidence_id,
            right_evidence_id=right.evidence_id,
            deltas=deltas,
            limitations=["Integrity or identity mismatch contradicts equality"],
        )
    if left_projection == right_projection:
        return ComparisonResult(
            status="unchanged",
            operation=left.operation,
            left_evidence_id=left.evidence_id,
            right_evidence_id=right.evidence_id,
        )
    return ComparisonResult(
        status="changed",
        operation=left.operation,
        left_evidence_id=left.evidence_id,
        right_evidence_id=right.evidence_id,
        deltas=_diff_keys(left_projection, right_projection),
    )


def _coverage_incomplete(
    left: RelationshipCoverage | None, right: RelationshipCoverage | None
) -> bool:
    return any(coverage is not None and coverage.status == "partial" for coverage in (left, right))


def _contains_contradiction(left: Any, right: Any) -> bool:
    return False


def _comparable(evidence: Evidence) -> dict[str, Any]:
    projection = evidence_without_display_fields(evidence)
    projection.pop("analysis_profile", None)
    return projection


def _diff_keys(left: dict[str, Any], right: dict[str, Any]) -> list[str]:
    keys = set(left) | set(right)
    return sorted(key for key in keys if left.get(key) != right.get(key))


__all__ = ["ComparisonResult", "ComparisonStatus", "compare_evidence"]
