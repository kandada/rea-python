"""Portable Evidence bundles.

A bundle is a deterministic, self-contained transfer format for a set of Evidence
records and unknown revisions. Import validates the whole bundle before any state
changes (atomic merge).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .analysis_error import EvidenceIntegrityError
from .evidence import Evidence
from .result import Result, err, ok

BUNDLE_SCHEMA_VERSION = 1


class EvidenceBundle(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = BUNDLE_SCHEMA_VERSION
    records: list[Evidence] = Field(default_factory=list)
    unknowns: list[dict[str, Any]] = Field(default_factory=list)


def create_evidence_bundle(
    records: list[Evidence],
    unknowns: list[dict[str, Any]] | None = None,
) -> EvidenceBundle:
    """Create a bundle with records in deterministic (evidence_id) order."""

    ordered = sorted(records, key=lambda record: record.evidence_id)
    return EvidenceBundle(records=ordered, unknowns=list(unknowns or []))


def parse_evidence_bundle(payload: Any) -> Result[EvidenceBundle, EvidenceIntegrityError]:
    try:
        bundle = EvidenceBundle.model_validate(payload)
    except Exception as cause:
        return err(
            EvidenceIntegrityError(
                message="Evidence bundle validation failed", details={"cause": str(cause)}
            )
        )
    if bundle.schema_version != BUNDLE_SCHEMA_VERSION:
        return err(
            EvidenceIntegrityError(
                message=f"Unsupported bundle schema version {bundle.schema_version}"
            )
        )
    # Re-authenticate every embedded record.
    for record in bundle.records:
        from .evidence import compute_evidence_id

        if compute_evidence_id(record) != record.evidence_id:
            return err(
                EvidenceIntegrityError(
                    message=f"Bundle record {record.evidence_id} failed authentication"
                )
            )
    return ok(bundle)


__all__ = [
    "BUNDLE_SCHEMA_VERSION",
    "EvidenceBundle",
    "create_evidence_bundle",
    "parse_evidence_bundle",
]
