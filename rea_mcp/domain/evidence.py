"""The Evidence model.

Every successful provider observation becomes an immutable, semantically-hashed
Evidence record. The ``evidence_id`` is derived from the *semantic* content
(excluding display-only fields such as the local path and subject name), so the
same fact keeps its identity across paths while tampering changes it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .analysis_error import EvidenceIntegrityError
from .analysis_profile import AnalysisProfile, ProviderIdentity
from .canonical import digest_canonical
from .coverage import RelationshipCoverage
from .json_value import normalize_json_value
from .locations import EvidenceLocation
from .result import Result, err, ok

Confidence = Literal["observed", "derived", "inferred"]
Authority = Literal[
    "shipped-artifact",
    "controlled-replay",
    "historical-reference",
    "external-service",
    "analyst-inference",
]


class ExecutionEnvironment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1)
    platform: str = Field(min_length=1)
    architecture: str = Field(min_length=1)
    isolation: Literal["none", "process", "container", "virtual-machine"] = "none"


class EvidenceSubject(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1)
    format: str = Field(min_length=1)
    architecture: str | None = None
    sha256: str = Field(min_length=1)
    local_path: str


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: str
    subject: EvidenceSubject | None
    provider: ProviderIdentity
    analysis_profile: AnalysisProfile | None
    predicate_type: str
    operation: str
    parameters: dict[str, Any]
    raw_result: Any | None
    normalized_result: Any
    confidence: Confidence = "observed"
    authority: Authority = "shipped-artifact"
    environment: ExecutionEnvironment | None = None
    limitations: list[str] = Field(default_factory=list)
    relationship_coverage: RelationshipCoverage | None = None
    locations: list[dict[str, Any]] = Field(default_factory=list)
    evidence_links: list[str] = Field(default_factory=list)


class EvidenceObservation:
    """Input to :func:`create_evidence` from a provider."""

    def __init__(
        self,
        operation: str,
        result: Any,
        *,
        parameters: dict[str, Any] | None = None,
        raw_result: Any | None = None,
        analysis_profile: AnalysisProfile | None = None,
        confidence: Confidence = "observed",
        authority: Authority = "shipped-artifact",
        environment: ExecutionEnvironment | None = None,
        limitations: list[str] | None = None,
        relationship_coverage: RelationshipCoverage | None = None,
        locations: list[EvidenceLocation | dict[str, Any]] | None = None,
        evidence_links: list[str] | None = None,
        predicate_type: str = "rea_mcp.analysis",
        subject_unavailable_reason: str | None = None,
    ) -> None:
        self.operation = operation
        self.result = result
        self.parameters = parameters or {}
        self.raw_result = raw_result
        self.analysis_profile = analysis_profile
        self.confidence = confidence
        self.authority = authority
        self.environment = environment
        self.limitations = list(limitations or [])
        self.relationship_coverage = relationship_coverage
        self.locations = list(locations or [])
        self.evidence_links = list(evidence_links or [])
        self.predicate_type = predicate_type
        self.subject_unavailable_reason = subject_unavailable_reason


def _subject_from_target(target: Any) -> EvidenceSubject | None:
    if target is None:
        return None
    path = getattr(target, "path", None)
    sha256 = getattr(target, "sha256", None)
    target_format = getattr(target, "format", "unknown")
    architecture = getattr(target, "architecture", None)
    if path is None or sha256 is None:
        return None
    name = Path(path).name or "artifact"
    return EvidenceSubject(
        name=name,
        format=target_format,
        architecture=architecture,
        sha256=sha256,
        local_path=path,
    )


def _semantic_projection(evidence: Evidence) -> dict[str, Any]:
    subject = evidence.subject
    return {
        "subject": (
            None
            if subject is None
            else {
                "format": subject.format,
                "architecture": subject.architecture,
                "sha256": subject.sha256,
            }
        ),
        "provider": evidence.provider.model_dump(),
        "analysis_profile": (
            None if evidence.analysis_profile is None else evidence.analysis_profile.model_dump()
        ),
        "predicate_type": evidence.predicate_type,
        "operation": evidence.operation,
        "parameters": evidence.parameters,
        "raw_result": evidence.raw_result,
        "normalized_result": evidence.normalized_result,
        "confidence": evidence.confidence,
        "authority": evidence.authority,
        "environment": None if evidence.environment is None else evidence.environment.model_dump(),
        "limitations": evidence.limitations,
        "relationship_coverage": (
            None
            if evidence.relationship_coverage is None
            else evidence.relationship_coverage.model_dump()
        ),
        "locations": evidence.locations,
        "evidence_links": evidence.evidence_links,
    }


def compute_evidence_id(evidence: Evidence) -> str:
    return f"ev_{digest_canonical(_semantic_projection(evidence))}"


def create_evidence(
    target: Any,
    provider: ProviderIdentity,
    observation: EvidenceObservation,
) -> Evidence:
    """Build deterministic Evidence from a provider observation."""

    subject = _subject_from_target(target)
    limitations = list(observation.limitations)
    if subject is None:
        reason = (
            observation.subject_unavailable_reason
            or "Artifact identity is unavailable for this observation."
        )
        limitations.insert(0, reason)

    normalized_locations = [
        location.model_dump() if isinstance(location, BaseModel) else location
        for location in observation.locations
    ]

    draft = Evidence(
        evidence_id=f"ev_{'0' * 64}",
        subject=subject,
        provider=provider,
        analysis_profile=observation.analysis_profile,
        predicate_type=observation.predicate_type,
        operation=observation.operation,
        parameters=normalize_json_value(observation.parameters),
        raw_result=(
            None if observation.raw_result is None else normalize_json_value(observation.raw_result)
        ),
        normalized_result=normalize_json_value(observation.result),
        confidence=observation.confidence,
        authority=observation.authority,
        environment=observation.environment,
        limitations=limitations,
        relationship_coverage=observation.relationship_coverage,
        locations=normalized_locations,
        evidence_links=list(observation.evidence_links),
    )
    return draft.model_copy(update={"evidence_id": compute_evidence_id(draft)})


def parse_evidence(payload: Any) -> Result[Evidence, EvidenceIntegrityError]:
    """Validate Evidence and verify its semantic identifier is intact."""

    try:
        evidence = Evidence.model_validate(payload)
    except Exception as cause:  # pydantic ValidationError and friends
        return err(
            EvidenceIntegrityError(
                message="Evidence validation failed", details={"cause": str(cause)}
            )
        )
    if compute_evidence_id(evidence) != evidence.evidence_id:
        return err(
            EvidenceIntegrityError(message="Evidence semantic identifier does not match its record")
        )
    return ok(evidence)


def evidence_without_display_fields(evidence: Evidence) -> dict[str, Any]:
    """Return the identity-bearing projection (no local path / subject name)."""

    return _semantic_projection(evidence)


__all__ = [
    "Authority",
    "Confidence",
    "Evidence",
    "EvidenceObservation",
    "EvidenceSubject",
    "ExecutionEnvironment",
    "compute_evidence_id",
    "create_evidence",
    "evidence_without_display_fields",
    "parse_evidence",
]
