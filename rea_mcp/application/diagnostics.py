"""Readiness reporting over the configured providers and external tools."""

from __future__ import annotations

from typing import Any

from ..providers.base import AnalysisProvider


def doctor_report(providers: list[AnalysisProvider]) -> dict[str, Any]:
    """Summarize provider and external-tool availability."""

    entries: list[dict[str, Any]] = []
    for provider in providers:
        identity = provider.identity()
        capabilities = provider.capabilities()
        unavailable = {
            descriptor.operation: descriptor.reason
            for descriptor in capabilities
            if not descriptor.available
        }
        entries.append(
            {
                "id": identity.id,
                "name": identity.name,
                "version": identity.version,
                "available": len(unavailable) == 0,
                "operations": [descriptor.operation for descriptor in capabilities],
                "unavailable_operations": unavailable,
            }
        )
    return {
        "healthy": all(entry["available"] for entry in entries),
        "provider_count": len(entries),
        "providers": entries,
    }


__all__ = ["doctor_report"]
