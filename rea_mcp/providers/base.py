"""Analysis provider foundation.

A provider declares its identity, capabilities (with side effects and limits), the
targets it supports, and how to run an operation against a target. Results are
returned as :class:`AnalysisExecution`, a provider-neutral observation that the
application layer turns into Evidence.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

from ..domain.analysis_error import AnalysisCapabilityUnavailableError, AnalysisError
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.coverage import RelationshipCoverage
from ..domain.locations import EvidenceLocation
from ..domain.result import Result, err

if TYPE_CHECKING:
    from .registry import TargetSupport


@dataclass(frozen=True)
class CapabilityEffects:
    mutates_artifact: bool = False
    launches_process: bool = False
    may_show_ui: bool = False
    may_access_network: bool = False
    may_write_filesystem: bool = False
    changes_permissions: bool = False
    requires_root: bool = False


@dataclass(frozen=True)
class CapabilityDescriptor:
    operation: str
    provider: ProviderIdentity
    available: bool = True
    reason: str | None = None
    effects: CapabilityEffects = field(default_factory=CapabilityEffects)
    limitations: tuple[str, ...] = ()
    cache_policy: Literal["snapshot", "live"] = "snapshot"


@dataclass(frozen=True)
class AnalysisExecution:
    """One atomic successful provider observation."""

    result: Any
    provider: ProviderIdentity
    raw_result: Any | None = None
    analysis_profile: AnalysisProfile | None = None
    limitations: tuple[str, ...] = ()
    relationship_coverage: RelationshipCoverage | None = None
    locations: tuple[EvidenceLocation | dict[str, Any], ...] = ()
    subject: Any | None = None
    cacheable: bool = True


class AnalysisProvider(ABC):
    """Provider-neutral analysis implementation for a set of operations."""

    @abstractmethod
    def identity(self) -> ProviderIdentity: ...

    @abstractmethod
    def capabilities(self) -> tuple[CapabilityDescriptor, ...]: ...

    @abstractmethod
    def supports(self, target: BinaryTarget) -> TargetSupport: ...

    @abstractmethod
    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]: ...

    def resolve_profile(self, target: BinaryTarget) -> AnalysisProfile | None:
        """Resolve the analysis profile for a target (side-effect free)."""

        return None

    def operation_names(self) -> tuple[str, ...]:
        return tuple(descriptor.operation for descriptor in self.capabilities())

    def capability(self, operation: str) -> CapabilityDescriptor | None:
        for descriptor in self.capabilities():
            if descriptor.operation == operation:
                return descriptor
        return None


class UnsupportedOperationMixin:
    """Helper to build a capability-unavailable error for an undeclared operation."""

    @staticmethod
    def unsupported(
        provider: ProviderIdentity, operation: str
    ) -> Result[AnalysisExecution, AnalysisError]:
        return err(
            AnalysisCapabilityUnavailableError(
                message=f"{provider.id} does not support {operation}",
                provider_id=provider.id,
                operation=operation,
                reason="operation is not declared by this provider",
            )
        )


__all__ = [
    "AnalysisExecution",
    "AnalysisProvider",
    "CapabilityDescriptor",
    "CapabilityEffects",
    "UnsupportedOperationMixin",
]
