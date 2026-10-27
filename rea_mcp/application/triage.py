"""Task-level, bounded target triage.

Triage runs a small, format-aware set of cheap observations in one call and
returns a compact evidence-backed summary plus next probes. It is intentionally
not a replacement for the individual analysis tools: callers can still retrieve
full Evidence and drill into any result.
"""

from __future__ import annotations

import time
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.result import Result, err, ok
from .session import BinarySession

_NATIVE_FORMATS = {"elf", "pe", "mach-o", "mach-o-universal", "raw-binary"}
_FACT_KEYS = (
    "format",
    "architecture",
    "package",
    "package_name",
    "main_activity",
    "version",
    "version_name",
    "min_sdk",
    "target_sdk",
    "title",
    "name",
    "count",
    "total",
    "file_count",
    "module_count",
    "section_count",
    "segment_count",
    "function_count",
    "procedure_count",
    "class_count",
    "method_count",
    "type_count",
    "entry_count",
    "export_count",
    "permission_count",
    "string_count",
    "route_count",
    "candidate_count",
    "source_count",
    "tool_count",
    "finding_count",
    "error_count",
)


def _candidates(target: Any) -> list[str]:
    fmt = str(target.format)
    if fmt in _NATIVE_FORMATS:
        operations = ["inspect_binary_layout", "inspect_native_exports"]
        if fmt == "pe":
            operations.extend(["inspect_pe_certificates", "inspect_pe_resources"])
        if fmt == "elf":
            operations.extend(["inspect_elf_notes", "inspect_go_binary", "inspect_rust_binary"])
        operations.append("inspect_artifact")
        return operations
    if fmt == "apk":
        return [
            "inspect_android_package",
            "inspect_apk_signature",
            "identify_flutter_build",
            "inspect_artifact",
        ]
    if fmt in ("asar", "directory"):
        return [
            "analyze_javascript_application",
            "inspect_javascript_routes",
            "inspect_javascript_dataflow",
        ]
    if fmt == "hap":
        return ["inspect_harmony_package", "inspect_artifact"]
    if fmt == "wasm":
        return ["inspect_wasm_artifact", "inspect_artifact"]
    if fmt in ("har", "saz"):
        return ["inspect_network_capture"]
    if fmt == "sqlite":
        return ["inspect_sqlite_database"]
    if fmt == "plist":
        return ["inspect_plist"]
    if fmt == "pcap":
        return ["inspect_pcap_capture"]
    if fmt in ("zip", "file", "unknown"):
        return ["inspect_artifact"]
    return ["inspect_binary_layout", "inspect_artifact"]


def _facts(result: Any) -> dict[str, Any]:
    if not isinstance(result, dict):
        return {}
    facts: dict[str, Any] = {}
    for key in _FACT_KEYS:
        value = result.get(key)
        if isinstance(value, (str, int, float, bool)) and not isinstance(value, bool):
            if isinstance(value, str) and len(value) > 200:
                value = value[:200]
            facts[key] = value
        elif isinstance(value, (str, int, float, bool)) and isinstance(value, bool):
            facts[key] = value
    if not facts:
        for key, value in result.items():
            if isinstance(value, (str, int, float, bool)) and not isinstance(value, bool):
                if isinstance(value, str) and len(value) > 200:
                    value = value[:200]
                facts[key] = value
                if len(facts) >= 8:
                    break
    for key, value in result.items():
        if isinstance(value, list) and key.endswith(("s", "list", "items")):
            facts.setdefault(f"{key}_count", len(value))
    return facts


def _next_probes(target: Any) -> list[dict[str, Any]]:
    fmt = str(target.format)
    if fmt in ("asar", "directory"):
        return [
            {"tool": "inspect_javascript_dataflow", "reason": "trace storage/DOM sinks"},
            {"tool": "inspect_javascript_webmcp", "reason": "discover declared tools"},
        ]
    if fmt == "apk":
        return [
            {"tool": "search_android_classes", "reason": "find entry points"},
            {"tool": "decompile_android_class", "reason": "inspect suspicious methods"},
        ]
    if fmt in _NATIVE_FORMATS:
        return [
            {"tool": "list_procedures", "reason": "choose a function to inspect"},
            {"tool": "decompile", "reason": "read a selected function"},
        ]
    if fmt == "hap":
        return [{"tool": "project_harmony_application_graph", "reason": "map abilities"}]
    return []


def triage_target(
    session: BinarySession,
    path: str | None = None,
    *,
    provider: str | None = None,
    question: str | None = None,
) -> Result[dict[str, Any], AnalysisError]:
    started = time.monotonic()
    if path is not None:
        opened = session.open(path, provider_id=provider)
        if not opened.ok:
            return err(opened.error)
    target = session.active_target()
    if target is None:
        return err(
            AnalysisInputError(operation="triage", message="no active target; supply a path")
        )
    probes: list[dict[str, Any]] = []
    failed: list[dict[str, str]] = []
    evidence_ids: list[str] = []
    for operation in _candidates(target):
        result = session.execute(operation, {})
        if not result.ok:
            failed.append({"operation": operation, "reason": result.error.message[:300]})
            continue
        evidence = result.value
        normalized = evidence.normalized_result
        probes.append(
            {
                "operation": operation,
                "provider": evidence.provider.id,
                "evidence_id": evidence.evidence_id,
                "confidence": evidence.confidence,
                "authority": evidence.authority,
                "facts": _facts(normalized),
                "limitations": list(evidence.limitations[:4]),
                "result_keys": sorted(normalized)[:30] if isinstance(normalized, dict) else [],
            }
        )
        evidence_ids.append(evidence.evidence_id)
    payload: dict[str, Any] = {
        "kind": "triage",
        "target": {
            "path": target.path,
            "format": target.format,
            "architecture": target.architecture,
            "sha256": target.sha256,
        },
        "question": question,
        "probe_count": len(probes),
        "failed_count": len(failed),
        "probes": probes,
        "failed_probes": failed,
        "evidence_ids": evidence_ids,
        "next_probes": _next_probes(target),
        "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
        "limitations": [
            "Triage runs a bounded format-specific probe set; it is not exhaustive.",
            "Use the referenced evidence IDs or individual tools for full detail.",
        ],
    }
    return ok(payload)


__all__ = ["triage_target"]
