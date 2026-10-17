"""Residual unknowns.

An unresolved analysis question is modelled as a versioned record with a stable
identity, supporting/contradicting evidence, and an explicit resolution. Unknowns
are first-class, so an honest investigation can carry "what is still not known".
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .analysis_error import UnknownRegistryError
from .canonical import digest_canonical
from .result import Result, err, ok

UnknownStatus = Literal["open", "investigating", "blocked", "contradicted", "resolved"]
UnknownSeverity = Literal["low", "medium", "high", "critical"]
RequiredConfidence = Literal["observed", "derived", "inferred"]
RequiredAuthority = Literal[
    "shipped-artifact",
    "controlled-replay",
    "historical-reference",
    "external-service",
    "analyst-inference",
]


class Probe(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    operation: str = Field(min_length=1)
    rationale: str = Field(min_length=1)


class Relationship(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    type: Literal["depends-on", "related-to", "contradicts"]
    unknown_id: str


class Resolution(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    disposition: Literal["verified", "withdrawn", "out-of-scope"]
    rationale: str = Field(min_length=1)
    evidence_ids: list[str] = Field(default_factory=list)


class ResidualUnknown(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    unknown_id: str
    revision: int = Field(ge=1)
    previous_revision_digest: str | None
    revision_digest: str
    scope_digest: str | None
    question: str
    status: UnknownStatus
    severity: UnknownSeverity
    domain: str
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    contradicting_evidence_ids: list[str] = Field(default_factory=list)
    required_authority: RequiredAuthority | None = None
    required_confidence: RequiredConfidence = "observed"
    recommended_probes: list[Probe] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    resolution: Resolution | None = None
    mutation_evidence_ids: list[str] = Field(default_factory=list)


def _normalize_question(question: str) -> str:
    return " ".join(question.split())


def stable_unknown_id(question: str, domain: str, scope_digest: str | None) -> str:
    return "unk_" + digest_canonical(
        {
            "domain": domain.strip(),
            "question": _normalize_question(question),
            "scope_digest": scope_digest,
        }
    )


def _revision_digest(payload: dict[str, Any]) -> str:
    return digest_canonical(payload)


class RecordUnknownInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    question: str = Field(min_length=1)
    domain: str = Field(min_length=1)
    severity: UnknownSeverity = "medium"
    scope_digest: str | None = None
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    contradicting_evidence_ids: list[str] = Field(default_factory=list)
    required_authority: RequiredAuthority | None = None
    required_confidence: RequiredConfidence = "observed"
    recommended_probes: list[Probe] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)


def create_residual_unknown(
    input: RecordUnknownInput, mutation_evidence_ids: list[str]
) -> ResidualUnknown:
    question = _normalize_question(input.question)
    domain = input.domain.strip()
    revision_payload: dict[str, Any] = {
        "unknown_id": stable_unknown_id(question, domain, input.scope_digest),
        "revision": 1,
        "previous_revision_digest": None,
        "scope_digest": input.scope_digest,
        "question": question,
        "status": "contradicted" if input.contradicting_evidence_ids else "open",
        "severity": input.severity,
        "domain": domain,
        "supporting_evidence_ids": sorted(set(input.supporting_evidence_ids)),
        "contradicting_evidence_ids": sorted(set(input.contradicting_evidence_ids)),
        "required_authority": input.required_authority,
        "required_confidence": input.required_confidence,
        "recommended_probes": [probe.model_dump() for probe in input.recommended_probes],
        "relationships": _sorted_relationships(input.relationships),
        "resolution": None,
        "mutation_evidence_ids": sorted(set(mutation_evidence_ids)),
    }
    return ResidualUnknown(**revision_payload, revision_digest=_revision_digest(revision_payload))


def update_residual_unknown(
    current: ResidualUnknown,
    *,
    status: UnknownStatus,
    severity: UnknownSeverity | None = None,
    supporting_evidence_ids: list[str] | None = None,
    contradicting_evidence_ids: list[str] | None = None,
    resolution: Resolution | None = None,
    mutation_evidence_id: str,
) -> Result[ResidualUnknown, UnknownRegistryError]:
    if status != "resolved" and resolution is not None:
        return err(
            UnknownRegistryError(
                reason="invalid-transition", message="Only resolved unknowns carry a resolution"
            )
        )
    if status == "resolved" and resolution is None:
        return err(
            UnknownRegistryError(
                reason="invalid-transition", message="Resolved status requires a resolution"
            )
        )
    if status == "contradicted" and not (
        contradicting_evidence_ids or current.contradicting_evidence_ids
    ):
        return err(
            UnknownRegistryError(
                reason="invalid-transition",
                message="Contradicted status requires contradicting evidence",
            )
        )
    revision_payload: dict[str, Any] = {
        "unknown_id": current.unknown_id,
        "revision": current.revision + 1,
        "previous_revision_digest": current.revision_digest,
        "scope_digest": current.scope_digest,
        "question": current.question,
        "status": status,
        "severity": severity or current.severity,
        "domain": current.domain,
        "supporting_evidence_ids": sorted(
            set(
                supporting_evidence_ids
                if supporting_evidence_ids is not None
                else current.supporting_evidence_ids
            )
        ),
        "contradicting_evidence_ids": sorted(
            set(
                contradicting_evidence_ids
                if contradicting_evidence_ids is not None
                else current.contradicting_evidence_ids
            )
        ),
        "required_authority": current.required_authority,
        "required_confidence": current.required_confidence,
        "recommended_probes": [probe.model_dump() for probe in current.recommended_probes],
        "relationships": _sorted_relationships(current.relationships),
        "resolution": None if resolution is None else resolution.model_dump(),
        "mutation_evidence_ids": sorted({*current.mutation_evidence_ids, mutation_evidence_id}),
    }
    return ok(
        ResidualUnknown(**revision_payload, revision_digest=_revision_digest(revision_payload))
    )


def _sorted_relationships(relationships: list[Relationship]) -> list[dict[str, str]]:
    return [
        relationship.model_dump()
        for relationship in sorted(relationships, key=lambda r: (r.type, r.unknown_id))
    ]


__all__ = [
    "Probe",
    "RecordUnknownInput",
    "Relationship",
    "ResidualUnknown",
    "Resolution",
    "UnknownSeverity",
    "UnknownStatus",
    "create_residual_unknown",
    "stable_unknown_id",
    "update_residual_unknown",
]
