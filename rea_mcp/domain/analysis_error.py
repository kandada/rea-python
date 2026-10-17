"""Tagged error algebra for REA-Python.

Every expected failure is a subclass of :class:`AnalysisError` carrying a stable
``tag``, a human message, any owned resources whose cleanup did not complete, and
an optional remediation action. Errors are projected into a serializable shape for
both CLI diagnostics and MCP tool errors.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, ClassVar


@dataclass
class AnalysisError(Exception):
    """Base class for all expected REA-Python failures."""

    tag: ClassVar[str] = "AnalysisError"

    message: str = ""
    cleanup_resources: list[str] = field(default_factory=list)
    remediation_action: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        super().__init__(self.message)

    @property
    def cleanup_incomplete(self) -> bool:
        return len(self.cleanup_resources) > 0

    def to_projection(self) -> dict[str, Any]:
        return {
            "error": {
                "code": _CODE_FOR_TAG.get(self.tag, self.tag),
                "tag": self.tag,
                "message": self.message,
                **(
                    {"remediation_action": self.remediation_action}
                    if self.remediation_action
                    else {}
                ),
                **({"details": self.details} if self.details else {}),
                **(
                    {"cleanup_resources": list(self.cleanup_resources)}
                    if self.cleanup_resources
                    else {}
                ),
            }
        }


@dataclass
class AnalysisInputError(AnalysisError):
    tag: ClassVar[str] = "AnalysisInputError"
    operation: str = "operation"


@dataclass
class AnalysisCapabilityUnavailableError(AnalysisError):
    tag: ClassVar[str] = "AnalysisCapabilityUnavailableError"
    provider_id: str = ""
    operation: str = ""
    reason: str = ""


@dataclass
class AnalysisCancelledError(AnalysisError):
    tag: ClassVar[str] = "AnalysisCancelledError"
    operation: str = "operation"

    def __post_init__(self) -> None:
        if not self.message:
            self.message = f"{self.operation} was cancelled"
        super().__post_init__()


@dataclass
class AnalysisOutputError(AnalysisError):
    tag: ClassVar[str] = "AnalysisOutputError"


@dataclass
class ProviderAdapterError(AnalysisError):
    tag: ClassVar[str] = "ProviderAdapterError"


@dataclass
class ProviderCleanupError(AnalysisError):
    tag: ClassVar[str] = "ProviderCleanupError"


@dataclass
class ProviderSelectionError(AnalysisError):
    tag: ClassVar[str] = "ProviderSelectionError"
    requested_provider_id: str = "auto"
    reason: str = "provider_unavailable"
    candidate_ids: list[str] = field(default_factory=list)
    rejections: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.message:
            self.message = (
                f"provider selection failed for {self.requested_provider_id!r}: {self.reason}"
            )
        super().__post_init__()


@dataclass
class NoBinaryOpenError(AnalysisError):
    tag: ClassVar[str] = "NoBinaryOpenError"

    def __post_init__(self) -> None:
        if not self.message:
            self.message = "No binary is open. Call open_binary first."
        super().__post_init__()


@dataclass
class AnalysisResourceConstraintError(AnalysisError):
    tag: ClassVar[str] = "AnalysisResourceConstraintError"
    resource: str = "transport"


@dataclass
class EvidenceIntegrityError(AnalysisError):
    tag: ClassVar[str] = "EvidenceIntegrityError"


@dataclass
class UnknownRegistryError(AnalysisError):
    tag: ClassVar[str] = "UnknownRegistryError"
    reason: str = "invalid-transition"

    def __post_init__(self) -> None:
        if not self.message:
            self.message = f"unknown registry error: {self.reason}"
        super().__post_init__()


@dataclass
class ArtifactChangedError(AnalysisError):
    tag: ClassVar[str] = "ArtifactChangedError"
    path: str = ""
    declared_sha256: str = ""
    observed_sha256: str = ""

    def __post_init__(self) -> None:
        if not self.message:
            self.message = (
                "The artifact changed after it was opened "
                f"({self.path}). Reopen the target and retry."
            )
        super().__post_init__()


_CODE_FOR_TAG: dict[str, str] = {
    "AnalysisInputError": "INVALID_INPUT",
    "AnalysisCapabilityUnavailableError": "CAPABILITY_UNAVAILABLE",
    "AnalysisCancelledError": "CANCELLED",
    "AnalysisOutputError": "OUTPUT_ERROR",
    "ProviderAdapterError": "PROVIDER_ADAPTER_ERROR",
    "ProviderCleanupError": "CLEANUP_INCOMPLETE",
    "ProviderSelectionError": "PROVIDER_SELECTION_FAILED",
    "NoBinaryOpenError": "NO_TARGET_OPEN",
    "AnalysisResourceConstraintError": "RESOURCE_CONSTRAINT",
    "EvidenceIntegrityError": "EVIDENCE_INTEGRITY",
    "UnknownRegistryError": "UNKNOWN_REGISTRY_ERROR",
    "ArtifactChangedError": "ARTIFACT_CHANGED",
}


def project_analysis_error(error: AnalysisError) -> dict[str, Any]:
    """Project any AnalysisError into its serializable diagnostic shape."""

    return error.to_projection()


def analysis_error_with_cleanup_failure(
    primary: AnalysisError,
    cleanup: AnalysisError,
    operation: str,
) -> AnalysisError:
    """Retain a primary failure while recording a later cleanup failure."""

    resources = list(cleanup.cleanup_resources)
    if not resources:
        resources = ["unknown-owned-resource"]
    combined = type(primary)(
        message=primary.message,
        cleanup_resources=resources,
        remediation_action=cleanup.remediation_action or primary.remediation_action,
        details={**primary.details, "cleanup_error": cleanup.to_projection()["error"]},
    )
    combined.details.setdefault("operation", operation)
    return combined


__all__ = [
    "AnalysisCancelledError",
    "AnalysisCapabilityUnavailableError",
    "AnalysisError",
    "AnalysisInputError",
    "AnalysisOutputError",
    "AnalysisResourceConstraintError",
    "ArtifactChangedError",
    "EvidenceIntegrityError",
    "NoBinaryOpenError",
    "ProviderAdapterError",
    "ProviderCleanupError",
    "ProviderSelectionError",
    "UnknownRegistryError",
    "analysis_error_with_cleanup_failure",
    "project_analysis_error",
]
