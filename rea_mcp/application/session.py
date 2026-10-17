"""The binary session: one active target shared by the CLI and MCP adapters.

The session binds the providers that support a target, routes each operation to
its declaring provider (providers own disjoint operations), records every
observation as Evidence, and caches successful profile-bound results for exact
replay.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..domain.analysis_error import (
    AnalysisCapabilityUnavailableError,
    AnalysisError,
    AnalysisInputError,
    NoBinaryOpenError,
)
from ..domain.analysis_profile import AnalysisProfile, create_analysis_profile
from ..domain.binary_target import BinaryTarget, TargetFormat, TargetKind, parse_binary_target
from ..domain.evidence import Evidence, EvidenceObservation, create_evidence
from ..domain.result import Result, err, ok
from ..providers.base import AnalysisExecution, AnalysisProvider
from ..providers.registry import AnalysisProviderRegistry
from .investigation import InvestigationRecords
from .snapshot import AnalysisSnapshot, AnalysisSnapshotCache, SnapshotEntry


@dataclass
class ActiveProvider:
    provider: AnalysisProvider
    profile: AnalysisProfile
    provider_id: str


class BinarySession:
    def __init__(
        self, registry: AnalysisProviderRegistry, records: InvestigationRecords | None = None
    ) -> None:
        self._registry = registry
        self._records = records or InvestigationRecords()
        self._target: BinaryTarget | None = None
        self._providers: list[ActiveProvider] = []
        self._requested_id: str = "auto"
        self._run_id: str | None = None
        self._snapshot = AnalysisSnapshotCache()

    # -- lifecycle ---------------------------------------------------------

    def open(
        self,
        path: str,
        *,
        provider_id: str | None = None,
        target_kind: TargetKind | None = None,
        format_hint: TargetFormat | None = None,
    ) -> Result[BinaryTarget, AnalysisError]:
        parsed = parse_binary_target(path, target_kind=target_kind, format_hint=format_hint)
        if not parsed.ok:
            return err(parsed.error)
        target = parsed.value
        requested = provider_id if provider_id is not None else self._registry.default_selector()
        applicable = self._registry.applicable_providers(target, requested)
        if not applicable.ok:
            return err(applicable.error)
        self._target = target
        self._requested_id = requested
        self._providers = [
            ActiveProvider(
                provider=provider,
                profile=provider.resolve_profile(target)
                or create_analysis_profile(provider.identity(), {"static": True}),
                provider_id=provider.identity().id,
            )
            for provider in applicable.value
        ]
        self._run_id = str(uuid.uuid4())
        primary = self._providers[0].profile if self._providers else None
        self._snapshot.bind(target, primary)
        return ok(target)

    def close(
        self, *, snapshot_path: str | None = None, overwrite: bool = False
    ) -> Result[dict[str, Any] | None, AnalysisError]:
        saved: dict[str, Any] | None = None
        if snapshot_path is not None:
            written = self.write_snapshot(snapshot_path, overwrite=overwrite)
            if not written.ok:
                return err(written.error)
            saved = written.value
        self._target = None
        self._providers = []
        self._run_id = None
        self._snapshot.invalidate()
        return ok(saved)

    def active_target(self) -> BinaryTarget | None:
        return self._target

    def _provider_for(self, operation: str) -> ActiveProvider | None:
        for active in self._providers:
            if active.provider.capability(operation) is not None:
                return active
        return None

    # -- execution ---------------------------------------------------------

    def execute(
        self, operation: str, parameters: dict[str, Any] | None = None
    ) -> Result[Evidence, AnalysisError]:
        parameters = parameters or {}
        execution = self.execute_execution(operation, parameters)
        if not execution.ok:
            return err(execution.error)
        evidence = self._to_evidence(operation, parameters, execution.value)
        recorded = self._records.record_evidence(evidence)
        if not recorded.ok:
            return err(recorded.error)
        return ok(evidence)

    def execute_execution(
        self, operation: str, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        if self._target is None:
            return err(NoBinaryOpenError())
        active = self._provider_for(operation)
        if active is None:
            declared = [
                descriptor.operation
                for candidate in self._providers
                for descriptor in candidate.provider.capabilities()
            ]
            return err(
                AnalysisCapabilityUnavailableError(
                    message=f"No bound provider supports {operation}",
                    provider_id=self._providers[0].provider_id if self._providers else "none",
                    operation=operation,
                    reason="operation is not declared by the bound providers",
                    details={"declared_operations": sorted(set(declared))},
                )
            )
        capability = active.provider.capability(operation)
        assert capability is not None
        cacheable = capability.cache_policy == "snapshot"
        if cacheable and self._snapshot.matches(self._target, active.profile):
            cached = self._snapshot.lookup(operation, parameters)
            if cached is not None:
                return ok(
                    AnalysisExecution(
                        result=cached.result,
                        provider=active.provider.identity(),
                        limitations=cached.limitations,
                    )
                )
        result = active.provider.analyze(operation, self._target, parameters, active.profile)
        if not result.ok:
            return result
        if cacheable:
            self._snapshot.record(
                SnapshotEntry(
                    operation=operation,
                    parameters=parameters,
                    result=result.value.result,
                    provider_id=active.provider_id,
                    limitations=result.value.limitations,
                )
            )
        return result

    def _to_evidence(
        self, operation: str, parameters: dict[str, Any], execution: AnalysisExecution
    ) -> Evidence:
        active = self._provider_for(operation)
        subject = execution.subject if execution.subject is not None else self._target
        observation = EvidenceObservation(
            operation=operation,
            result=execution.result,
            parameters=parameters,
            raw_result=execution.raw_result,
            analysis_profile=execution.analysis_profile or (active.profile if active else None),
            limitations=list(execution.limitations),
            relationship_coverage=execution.relationship_coverage,
            locations=list(execution.locations),
        )
        return create_evidence(subject, execution.provider, observation)

    # -- snapshots ---------------------------------------------------------

    def write_snapshot(
        self, path: str, *, overwrite: bool = False
    ) -> Result[dict[str, Any], AnalysisError]:
        if self._target is None:
            return err(NoBinaryOpenError())
        destination = Path(path)
        if destination.exists() and not overwrite:
            return err(
                AnalysisInputError(
                    operation="close_binary", message=f"Snapshot destination already exists: {path}"
                )
            )
        snapshot = self._snapshot.export_snapshot()
        destination.write_text(json.dumps(snapshot.to_payload(), indent=2), encoding="utf-8")
        return ok(
            {
                "path": str(destination),
                "primitive_entries": len(snapshot.entries),
                "provider_id": snapshot.provider_id,
            }
        )

    def import_snapshot(self, payload: dict[str, Any]) -> Result[None, AnalysisError]:
        snapshot = AnalysisSnapshot.from_payload(payload)
        if not self._snapshot.import_snapshot(snapshot):
            return err(
                AnalysisInputError(
                    operation="open_binary",
                    message="Snapshot profile_mismatch: target does not match the open session",
                )
            )
        return ok(None)

    # -- records -----------------------------------------------------------

    def export_bundle(self) -> dict[str, Any]:
        bundle: dict[str, Any] = self._records.ledger.export_bundle().model_dump()
        return bundle

    def import_bundle(self, payload: Any) -> Result[Any, AnalysisError]:
        return self._records.ledger.import_bundle(payload)

    def evidence_records(self) -> list[Evidence]:
        return self._records.ledger.records()

    def list_unknowns(self) -> list[Any]:
        return [unknown.model_dump() for unknown in self._records.list_unknowns()]

    # -- introspection -----------------------------------------------------

    def status(self) -> dict[str, Any]:
        candidates = self._registry.candidates(self._target)
        bound_ids = {active.provider_id for active in self._providers}
        return {
            "open": self._target is not None,
            "target": None if self._target is None else self._target.model_dump(),
            "requested_provider_id": self._requested_id,
            "bound_providers": [
                {
                    "id": active.provider_id,
                    "profile_digest": active.profile.digest,
                    "operations": list(active.provider.operation_names()),
                }
                for active in self._providers
            ],
            "run_id": self._run_id,
            "evidence_count": self._records.ledger.record_count,
            "snapshot_entries": self._snapshot.entry_count,
            "provider_candidates": [
                {
                    "id": candidate.provider_id,
                    "supports_target": candidate.supports_target,
                    "selected": candidate.provider_id in bound_ids,
                    "operations": list(candidate.operations),
                }
                for candidate in candidates
            ],
        }

    def providers(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for provider_id in self._registry.identities():
            capabilities = self._registry.capabilities_for(provider_id)
            result.append(
                {
                    "id": provider_id,
                    "operations": [descriptor.operation for descriptor in capabilities],
                }
            )
        return result


__all__ = ["ActiveProvider", "BinarySession"]
