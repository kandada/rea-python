"""Analysis provider registry with deterministic selection.

Candidates are ordered by provider id (Unicode code point). Registration order never
affects selection or output. Selection never falls back automatically: an explicit
provider runs only if it supports the target, ``auto`` selects the single usable
candidate, and multiple usable candidates is an explicit ``ambiguous`` error.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ..domain.analysis_error import (
    AnalysisError,
    ProviderSelectionError,
)
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisProvider, CapabilityDescriptor

SupportStatus = Literal["supported", "unsupported", "unknown"]


@dataclass(frozen=True)
class TargetSupport:
    status: SupportStatus
    reason: str | None = None
    code: str | None = None


@dataclass(frozen=True)
class CandidateStatus:
    provider_id: str
    provider_name: str
    version: str | None
    supports_target: SupportStatus
    selected: bool
    operations: tuple[str, ...]


@dataclass(frozen=True)
class ProviderBinding:
    provider: AnalysisProvider
    provider_id: str
    selection_source: Literal["request", "environment", "auto-single-candidate"]


@dataclass(frozen=True)
class Selection:
    requested_provider_id: str
    binding: ProviderBinding | None
    candidates: tuple[CandidateStatus, ...]


class AnalysisProviderRegistry:
    def __init__(self, providers: list[AnalysisProvider], default_selector: str = "auto") -> None:
        by_id: dict[str, AnalysisProvider] = {}
        for provider in providers:
            identity = provider.identity()
            if identity.id in by_id:
                raise TypeError(f"Duplicate analysis provider ID: {identity.id}")
            for descriptor in provider.capabilities():
                if descriptor.provider.id != identity.id:
                    raise TypeError(
                        f"Provider {identity.id} published mismatched capability provenance "
                        f"for {descriptor.operation}"
                    )
            by_id[identity.id] = provider
        self._providers = sorted(providers, key=lambda provider: provider.identity().id)
        self._by_id = by_id
        self._default_selector = default_selector

    def default_selector(self) -> str:
        return self._default_selector

    def identities(self) -> list[str]:
        return [provider.identity().id for provider in self._providers]

    def declared_operations(self) -> tuple[str, ...]:
        operations: set[str] = set()
        for provider in self._providers:
            operations.update(provider.operation_names())
        return tuple(sorted(operations))

    def capabilities_for(self, provider_id: str) -> tuple[CapabilityDescriptor, ...]:
        provider = self._by_id.get(provider_id)
        return () if provider is None else provider.capabilities()

    def candidates(self, target: BinaryTarget | None = None) -> tuple[CandidateStatus, ...]:
        statuses: list[CandidateStatus] = []
        for provider in self._providers:
            identity = provider.identity()
            support = "unknown" if target is None else provider.supports(target).status
            statuses.append(
                CandidateStatus(
                    provider_id=identity.id,
                    provider_name=identity.name,
                    version=identity.version,
                    supports_target=support,
                    selected=False,
                    operations=provider.operation_names(),
                )
            )
        return tuple(statuses)

    def applicable_providers(
        self,
        target: BinaryTarget,
        requested: str | None = None,
    ) -> Result[list[AnalysisProvider], AnalysisError]:
        """Return the providers usable for a target.

        An explicit id must exist and support the target; otherwise every provider
        that supports the target is returned. Providers own disjoint operations, so
        the session routes each operation to its declaring provider.
        """

        if requested is not None and requested != "auto":
            provider = self._by_id.get(requested)
            if provider is None:
                return err(
                    _selection_error(
                        "unknown_provider", requested, self._candidates_with_support(target)
                    )
                )
            if provider.supports(target).status != "supported":
                return err(
                    _selection_error(
                        "target_unsupported", requested, self._candidates_with_support(target)
                    )
                )
            return ok([provider])
        usable = [
            provider
            for provider in self._providers
            if provider.supports(target).status == "supported"
        ]
        if not usable:
            return err(
                _selection_error(
                    "target_unsupported", "auto", self._candidates_with_support(target)
                )
            )
        return ok(usable)

    def provider_by_id(self, provider_id: str) -> AnalysisProvider | None:
        return self._by_id.get(provider_id)

    def select(
        self,
        target: BinaryTarget,
        requested: str | None = None,
    ) -> Result[Selection, AnalysisError]:
        selector = requested if requested is not None else self._default_selector
        if selector not in ("auto",) and selector not in self._by_id:
            return err(
                _selection_error(
                    "unknown_provider", selector, self._candidates_with_support(target)
                )
            )
        if selector != "auto":
            return self._select_concrete(
                target, selector, "request" if requested is not None else "environment"
            )
        return self._select_automatically(target)

    def _select_concrete(
        self,
        target: BinaryTarget,
        provider_id: str,
        source: Literal["request", "environment"],
    ) -> Result[Selection, AnalysisError]:
        provider = self._by_id[provider_id]
        support = provider.supports(target)
        statuses = _replace_status(self.candidates(target), provider_id, True)
        if support.status != "supported":
            return err(_selection_error("target_unsupported", provider_id, statuses))
        return ok(
            Selection(
                requested_provider_id=provider_id,
                binding=ProviderBinding(
                    provider=provider, provider_id=provider_id, selection_source=source
                ),
                candidates=statuses,
            )
        )

    def _select_automatically(self, target: BinaryTarget) -> Result[Selection, AnalysisError]:
        statuses = self._candidates_with_support(target)
        usable = [
            provider
            for provider in self._providers
            if provider.supports(target).status == "supported"
        ]
        if len(usable) == 0:
            return ok(Selection(requested_provider_id="auto", binding=None, candidates=statuses))
        if len(usable) > 1:
            return err(_selection_error("ambiguous", "auto", statuses))
        provider = usable[0]
        provider_id = provider.identity().id
        return ok(
            Selection(
                requested_provider_id="auto",
                binding=ProviderBinding(
                    provider=provider,
                    provider_id=provider_id,
                    selection_source="auto-single-candidate",
                ),
                candidates=_replace_status(statuses, provider_id, True),
            )
        )

    def _candidates_with_support(self, target: BinaryTarget) -> tuple[CandidateStatus, ...]:
        return self.candidates(target)

    def unbound_error(self, operation: str, selection: Selection) -> ProviderSelectionError:
        every_unsupported = len(selection.candidates) > 0 and all(
            candidate.supports_target == "unsupported" for candidate in selection.candidates
        )
        reason = "target_unsupported" if every_unsupported else "provider_unavailable"
        return _selection_error(
            reason, selection.requested_provider_id, selection.candidates, operation
        )


def _replace_status(
    statuses: tuple[CandidateStatus, ...], provider_id: str, selected: bool
) -> tuple[CandidateStatus, ...]:
    return tuple(
        CandidateStatus(
            provider_id=status.provider_id,
            provider_name=status.provider_name,
            version=status.version,
            supports_target=status.supports_target,
            selected=selected if status.provider_id == provider_id else status.selected,
            operations=status.operations,
        )
        for status in statuses
    )


def _selection_error(
    reason: str,
    requested_provider_id: str,
    candidates: tuple[CandidateStatus, ...],
    operation: str = "open_binary",
) -> ProviderSelectionError:
    return ProviderSelectionError(
        message=f"provider selection failed for {requested_provider_id!r}: {reason}",
        requested_provider_id=requested_provider_id,
        reason=reason,
        candidate_ids=[candidate.provider_id for candidate in candidates],
        rejections=[
            {
                "provider_id": candidate.provider_id,
                "reason": candidate.supports_target,
            }
            for candidate in candidates
            if candidate.supports_target == "unsupported"
        ],
        details={"operation": operation},
    )


__all__ = [
    "AnalysisProviderRegistry",
    "CandidateStatus",
    "ProviderBinding",
    "Selection",
    "SupportStatus",
    "TargetSupport",
]
