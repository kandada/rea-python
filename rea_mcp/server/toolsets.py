"""MCP tool exposure presets.

The full catalog is useful for compatibility and research, but it is expensive to
advertise to an agent. Presets keep the default surface small and let callers opt
into a domain or the complete catalog.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from fnmatch import fnmatch

from ..contracts.tool_contracts import TOOL_CONTRACTS

CORE_TOOLS: frozenset[str] = frozenset(
    {
        "open_binary",
        "close_binary",
        "binary_session",
        "providers",
        "doctor",
        "triage",
        "inspect_binary_layout",
        "inspect_artifact",
        "analyze",
        "function",
        "decompile",
        "search",
        "list_strings",
        "xrefs",
        "compare_evidence",
        "evidence_export",
        "evidence_import",
        "inspect_analysis_view",
        "get_evidence_bundle",
    }
)

_DOMAIN_PATTERNS: dict[str, tuple[str, ...]] = {
    "native": (
        "inspect_binary_layout",
        "inspect_elf_notes",
        "inspect_go_binary",
        "inspect_rust_binary",
        "inspect_native_*",
        "inspect_pe_*",
        "inspect_with_objdump",
        "analyze",
        "function",
        "decompile",
        "search",
        "xrefs",
        "instructions",
        "list_*",
        "procedure_*",
        "read_function_instructions",
        "trace_native_*",
        "resolve_native_*",
        "match_native_functions",
        "analyze_swift_types",
        "get_objc_*",
        "inspect_address_context",
        "inspect_navigation_context",
        "inspect_native_*",
        "trace_call_path",
        "trace_feature",
        "trace_native_values",
        "get_call_graph",
        "build_call_path",
        "batch_decompile",
        "compare_functions",
    ),
    "web": (
        "*web*",
        "*javascript*",
        "*electron*",
        "*browser*",
        "*cdp*",
        "capture_browser_scenario",
        "capture_electron_scenario",
        "list_javascript_runtime_targets",
        "observe_javascript_runtime",
        "reconcile_javascript_runtime",
        "export_web_scripts",
        "recover_javascript_sources",
        "trace_web_*",
        "discover_webmcp_tools",
        "invoke_webmcp_tool",
    ),
    "android": (
        "*android*",
        "*apk*",
        "*adb*",
        "*flutter*",
        "*harmony*",
        "capture_adb_screen",
        "collect_adb_bugreport",
        "identify_flutter_build",
        "inspect_dart_aot",
        "project_harmony_application_graph",
    ),
    "managed": (
        "*managed*",
        "*dotnet*",
        "*csharp*",
        "inspect_pe_resources",
        "inspect_pe_certificates",
        "inspect_managed_*",
        "disassemble_managed_method",
        "project_managed_application_graph",
    ),
    "external": (
        "ghidra_*",
        "ida_*",
        "jeb_*",
        "hopper_*",
        "kuna_*",
        "rizin_*",
        "frida_*",
        "gdb_*",
        "start_gdb_session",
        "start_rizin_debug_session",
        "start_frida_session",
        "instrument_with_frida",
        "list_cutter_sessions",
        "cutter_command",
        "execute_rizin_command",
    ),
    "environment": ("environment_*",),
    "evidence": (
        "compare_*",
        "evidence_*",
        "get_evidence_bundle",
        "inspect_analysis_view",
        "snapshot_*",
        "build_reconstruction_*",
        "evaluate_reconstruction_*",
        "verify_*",
        "record_unknown",
        "update_unknown",
        "list_unknowns",
        "find_changed_behavior",
        "correlate_static_and_runtime",
        "capture_process*",
    ),
}

# Names that are intentionally not part of a profile unless the domain matches.
_FULL_ALIASES = {"all", "full", "*"}
_CONTRACT_OPERATIONS = {contract.name: contract.operation for contract in TOOL_CONTRACTS}


def _matches(name: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch(name, pattern) for pattern in patterns)


def named_toolset(name: str) -> str:
    normalized = name.strip().lower()
    if normalized in ("", "auto"):
        return "auto"
    if normalized in _FULL_ALIASES:
        return "full"
    return normalized


def resolve_toolset(name: str, *, client: str = "generic") -> frozenset[str] | None:
    """Return allowed tool names, or ``None`` for the complete catalog."""

    normalized = named_toolset(name)
    if normalized == "auto":
        normalized = (
            "core"
            if client.lower() in {"cursor", "opencode", "vscode", "code", "zed", "minimal"}
            else "full"
        )
    if normalized in _FULL_ALIASES:
        return None
    allowed = set(CORE_TOOLS)
    if normalized == "core":
        return frozenset(allowed)
    for part in normalized.split(","):
        part = part.strip()
        if not part:
            continue
        if part in _FULL_ALIASES:
            return None
        patterns = _DOMAIN_PATTERNS.get(part)
        if patterns is None:
            raise ValueError(f"unknown MCP toolset: {part}")
        allowed.update(pattern for pattern in patterns)
    return frozenset(allowed)


def toolset_filter(
    name: str,
    *,
    client: str = "generic",
    available_operations: set[str] | None = None,
) -> Callable[[str], bool]:
    """Build a predicate for ``FastMCP.list_tools``.

    ``available_operations`` applies to tools with a declared contract operation;
    tools without a contract remain visible because their provider is not known
    from the static catalog.
    """

    allowed = resolve_toolset(name, client=client)

    def predicate(tool_name: str) -> bool:
        if allowed is not None and tool_name not in allowed and not _matches(tool_name, allowed):
            return False
        operation = _CONTRACT_OPERATIONS.get(tool_name)
        if available_operations is not None and operation is not None:
            return operation in available_operations
        return True

    return predicate


def resolve_toolset_names(
    names: Iterable[str], *, toolset: str = "auto", client: str = "generic"
) -> set[str]:
    predicate = toolset_filter(toolset, client=client)
    return {name for name in names if predicate(name)}


__all__ = [
    "CORE_TOOLS",
    "named_toolset",
    "resolve_toolset",
    "resolve_toolset_names",
    "toolset_filter",
]
