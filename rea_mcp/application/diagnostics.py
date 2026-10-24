"""Readiness reporting over the configured providers and external tools."""

from __future__ import annotations

import os
from typing import Any

from ..providers.base import AnalysisProvider

CORE_PROVIDER_IDS = (
    "binary-layout",
    "dotnet",
    "artifacts",
    "sqlite",
    "android",
    "javascript",
    "plist",
    "pe-resources",
    "network-capture",
)

PROFILE_PROVIDER_IDS: dict[str, tuple[str, ...]] = {
    "core": CORE_PROVIDER_IDS,
    "powerbi": ("binary-layout", "dotnet", "artifacts"),
    "android": ("android", "android-deep"),
    "web": ("javascript", "electron", "web-runtime", "cdp"),
}


def doctor_report(
    providers: list[AnalysisProvider],
    *,
    required: list[str] | None = None,
    profile: str | None = None,
) -> dict[str, Any]:
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
    available = {entry["id"] for entry in entries if entry["available"]}
    if required is None and profile is not None:
        required = list(PROFILE_PROVIDER_IDS.get(profile.lower(), ()))
    if required is None:
        required = list(CORE_PROVIDER_IDS)
    required_ids = list(dict.fromkeys(required))
    missing_required = [provider_id for provider_id in required_ids if provider_id not in available]
    healthy_core = not [
        provider_id for provider_id in CORE_PROVIDER_IDS if provider_id not in available
    ]
    healthy_all = all(entry["available"] for entry in entries)
    return {
        "healthy": healthy_all,
        "healthy_all": healthy_all,
        "healthy_core": healthy_core,
        "healthy_required": not missing_required,
        "profile": profile,
        "required": required_ids,
        "missing_required": missing_required,
        "provider_count": len(entries),
        "providers": entries,
        "environment": {
            "jadx_operation_timeout_ms": timeout_ms,
            "jadx_operation_timeout_source": timeout_source,
        },
    }


__all__ = ["doctor_report"]
