"""Readiness/coverage projection for an environment state."""

from __future__ import annotations

from typing import Any

from .state_store import EnvironmentStateStore


def environment_coverage(
    store: EnvironmentStateStore, required_types: list[str] | None = None
) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for entity in store.entities.values():
        key = str(entity.get("type"))
        counts[key] = counts.get(key, 0) + 1
    required = required_types or [str(item.get("collection_template")) for item in store.types]
    missing = [name for name in required if counts.get(name, 0) == 0]
    return {
        "entity_count": len(store.entities),
        "document_count": len(store.documents),
        "counts": counts,
        "required_types": required,
        "missing_types": missing,
        "document_tools": sorted(store.documents.keys()),
        "write_clock": store.write_clock,
        "digest": store.digest(),
        "coverage": {"state": "partial" if missing else "complete", "missing": missing},
        "limitations": (["Some declared types have no observed entities."] if missing else []),
    }


__all__ = ["environment_coverage"]
