"""Readiness reporting over the configured providers and external tools."""

from __future__ import annotations

import os
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
    timeout_raw = os.environ.get("REA_JADX_OPERATION_TIMEOUT_MS")
    timeout_ms = 120_000
    timeout_source = "default"
    if timeout_raw:
        try:
            parsed = int(timeout_raw)
            if 1 <= parsed <= 2_147_483_647:
                timeout_ms = parsed
                timeout_source = "environment"
            else:
                timeout_source = "invalid"
        except ValueError:
            timeout_source = "invalid"
    return {
        "healthy": all(entry["available"] for entry in entries),
        "provider_count": len(entries),
        "providers": entries,
        "environment": {
            "jadx_operation_timeout_ms": timeout_ms,
            "jadx_operation_timeout_source": timeout_source,
        },
    }


__all__ = ["doctor_report"]
