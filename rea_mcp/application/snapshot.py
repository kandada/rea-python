"""Analysis snapshot cache.

A snapshot retains successful, profile-bound observations so an exact repeat query
can be replayed without re-running the provider. Keys cover every result-affecting
input: target identity, analysis profile, operation, and parameters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..domain.analysis_profile import AnalysisProfile
from ..domain.binary_target import BinaryTarget
from ..domain.canonical import digest_canonical


@dataclass
class SnapshotEntry:
    operation: str
    parameters: dict[str, Any]
    result: Any
    provider_id: str
    limitations: tuple[str, ...] = ()


@dataclass
class AnalysisSnapshot:
    target_sha256: str
    target_path: str
    profile_digest: str | None
    provider_id: str | None
    entries: list[SnapshotEntry] = field(default_factory=list)

    def to_payload(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "target": {"sha256": self.target_sha256, "path": self.target_path},
            "profile_digest": self.profile_digest,
            "provider_id": self.provider_id,
            "entries": [
                {
                    "operation": entry.operation,
                    "parameters": entry.parameters,
                    "result": entry.result,
                    "provider_id": entry.provider_id,
                    "limitations": list(entry.limitations),
                }
                for entry in self.entries
            ],
        }

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> AnalysisSnapshot:
        target = payload.get("target", {})
        return cls(
            target_sha256=target.get("sha256", ""),
            target_path=target.get("path", ""),
            profile_digest=payload.get("profile_digest"),
            provider_id=payload.get("provider_id"),
            entries=[
                SnapshotEntry(
                    operation=entry["operation"],
                    parameters=entry.get("parameters", {}),
                    result=entry.get("result"),
                    provider_id=entry.get("provider_id", ""),
                    limitations=tuple(entry.get("limitations", [])),
                )
                for entry in payload.get("entries", [])
            ],
        )


class AnalysisSnapshotCache:
    """A cache bound to one target and profile at a time."""

    def __init__(self) -> None:
        self._entries: dict[str, SnapshotEntry] = {}
        self._target_sha256: str | None = None
        self._target_path: str | None = None
        self._profile_digest: str | None = None
        self._provider_id: str | None = None

    def bind(self, target: BinaryTarget, profile: AnalysisProfile | None) -> None:
        self._target_sha256 = target.sha256
        self._target_path = target.path
        self._profile_digest = profile.digest if profile is not None else None
        self._provider_id = profile.provider.id if profile is not None else None
        self._entries.clear()

    def matches(self, target: BinaryTarget, profile: AnalysisProfile | None) -> bool:
        profile_digest = profile.digest if profile is not None else None
        return (
            self._target_sha256 == target.sha256
            and self._profile_digest == profile_digest
            and self._entries is not None
        )

    def invalidate(self) -> None:
        self._entries.clear()

    @staticmethod
    def _key(operation: str, parameters: dict[str, Any]) -> str:
        return f"{operation}:{digest_canonical({'op': operation, 'params': parameters})}"

    def lookup(self, operation: str, parameters: dict[str, Any]) -> SnapshotEntry | None:
        return self._entries.get(self._key(operation, parameters))

    def record(self, entry: SnapshotEntry) -> None:
        self._entries[self._key(entry.operation, entry.parameters)] = entry

    def export_snapshot(self) -> AnalysisSnapshot:
        return AnalysisSnapshot(
            target_sha256=self._target_sha256 or "",
            target_path=self._target_path or "",
            profile_digest=self._profile_digest,
            provider_id=self._provider_id,
            entries=list(self._entries.values()),
        )

    def import_snapshot(self, snapshot: AnalysisSnapshot) -> bool:
        if self._target_sha256 is not None and snapshot.target_sha256 != self._target_sha256:
            return False
        self._entries = {
            self._key(entry.operation, entry.parameters): entry for entry in snapshot.entries
        }
        if self._target_sha256 is None:
            self._target_sha256 = snapshot.target_sha256
            self._target_path = snapshot.target_path
            self._profile_digest = snapshot.profile_digest
            self._provider_id = snapshot.provider_id
        return True

    @property
    def entry_count(self) -> int:
        return len(self._entries)


__all__ = ["AnalysisSnapshot", "AnalysisSnapshotCache", "SnapshotEntry"]
