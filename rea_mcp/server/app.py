"""MCP adapter: exposes the session's operations as MCP tools over stdio."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from ..application.analysis_view import load_view
from ..application.diagnostics import doctor_report
from ..application.process_capture import capture_process as capture_process_op
from ..application.session import BinarySession
from ..composition.factories import build_providers
from ..config.settings import AppConfig
from ..contracts.schemas import compact_input_schema
from ..contracts.tool_contracts import TOOL_CONTRACTS
from ..domain.analysis_error import AnalysisInputError, NoBinaryOpenError, project_analysis_error
from ..domain.binary_target import TargetFormat, TargetKind
from ..domain.comparison import compare_evidence as compare_evidence_fn
from ..domain.evidence import parse_evidence

_ANALYSIS_TOOLS = [
    contract for contract in TOOL_CONTRACTS if contract.requires_target and contract.operation
]


def _error_payload(error: Any) -> str:
    return json.dumps(project_analysis_error(error), ensure_ascii=False)


def _open_if_needed(session: BinarySession, path: str | None) -> None:
    active = session.active_target()
    if path is None:
        if active is None:
            raise ToolError(_error_payload(NoBinaryOpenError()))
        return
    if active is not None and Path(active.path) == Path(path):
        return
    opened = session.open(path)
    if not opened.ok:
        raise ToolError(_error_payload(opened.error))


def _analysis(
    session: BinarySession, operation: str, path: str | None, parameters: dict[str, Any]
) -> dict[str, Any]:
    _open_if_needed(session, path)
    result = session.execute(operation, parameters)
    if not result.ok:
        raise ToolError(_error_payload(result.error))
    return result.value.model_dump()


class _SchemaProfileFastMCP(FastMCP):
    """FastMCP that optionally compacts advertised input schemas."""

    def __init__(
        self,
        *args: Any,
        compact_budget: int | None = None,
        omit_output_schemas: bool = False,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._compact_budget = compact_budget
        self._omit_output_schemas = omit_output_schemas

    async def list_tools(self) -> list[Any]:
        tools = await super().list_tools()
        if self._compact_budget is None and not self._omit_output_schemas:
            return tools
        transformed = []
        for tool in tools:
            update: dict[str, Any] = {}
            if self._compact_budget is not None:
                update["inputSchema"] = compact_input_schema(tool.inputSchema, self._compact_budget)
            if self._omit_output_schemas:
                update["outputSchema"] = None
            transformed.append(tool.model_copy(update=update))
        return transformed


def build_mcp_server(session: BinarySession, config: AppConfig | None = None) -> FastMCP:
    config = config or AppConfig()
    compact_budget = 13312 if config.effective_input_schema_profile == "compact" else None
    server = _SchemaProfileFastMCP(
        compact_budget=compact_budget,
        name="rea-mcp",
        instructions=(
            "Reverse engineer local binaries and artifacts with evidence. "
            "Open a target with open_binary, then call the inspect_* tools. "
            "Every result is Evidence with confidence, authority and limitations."
        ),
    )

    @server.tool(name="open_binary", description="Open a local target and bind a provider.")
    def open_binary(
        path: str,
        provider_id: str | None = None,
        target_kind: str | None = None,
        format_hint: str | None = None,
    ) -> dict[str, Any]:
        opened = session.open(
            path,
            provider_id=provider_id,
            target_kind=cast("TargetKind | None", target_kind),
            format_hint=cast("TargetFormat | None", format_hint),
        )
        if not opened.ok:
            raise ToolError(_error_payload(opened.error))
        return {"open": True, "target": opened.value.model_dump()}

    @server.tool(name="close_binary", description="Close the active target.")
    def close_binary(snapshot_path: str | None = None, overwrite: bool = False) -> dict[str, Any]:
        closed = session.close(snapshot_path=snapshot_path, overwrite=overwrite)
        if not closed.ok:
            raise ToolError(_error_payload(closed.error))
        return {"open": False, "snapshot": closed.value}

    @server.tool(name="binary_session", description="Report the session, tools and providers.")
    def binary_session() -> dict[str, Any]:
        return session.status()

    @server.tool(name="providers", description="List configured providers and their operations.")
    def providers() -> dict[str, Any]:
        return {"providers": session.providers()}

    @server.tool(
        name="inspect_binary_layout", description="Sections, segments, symbols and mitigations."
    )
    def inspect_binary_layout(path: str | None = None) -> dict[str, Any]:
        return _analysis(session, "inspect_binary_layout", path, {})

    @server.tool(name="inspect_go_binary", description="Embedded Go metadata.")
    def inspect_go_binary(path: str | None = None) -> dict[str, Any]:
        return _analysis(session, "inspect_go_binary", path, {})

    @server.tool(name="inspect_rust_binary", description="cargo-auditable dependency inventory.")
    def inspect_rust_binary(path: str | None = None) -> dict[str, Any]:
        return _analysis(session, "inspect_rust_binary", path, {})

    @server.tool(name="inspect_managed_artifact", description="Static .NET/CLI metadata.")
    def inspect_managed_artifact(path: str | None = None) -> dict[str, Any]:
        return _analysis(session, "inspect_managed_artifact", path, {})

    @server.tool(name="inspect_sqlite_database", description="SQLite schema and bounded rows.")
    def inspect_sqlite_database(
        path: str | None = None, table: str | None = None, row_limit: int = 20
    ) -> dict[str, Any]:
        return _analysis(
            session, "inspect_sqlite_database", path, {"table": table, "row_limit": row_limit}
        )

    @server.tool(
        name="inspect_artifact", description="File inventory for archives and directories."
    )
    def inspect_artifact(path: str | None = None) -> dict[str, Any]:
        return _analysis(session, "inspect_artifact", path, {})

    @server.tool(
        name="inspect_android_package", description="APK inventory, DEX and manifest facts."
    )
    def inspect_android_package(path: str | None = None) -> dict[str, Any]:
        return _analysis(session, "inspect_android_package", path, {})

    @server.tool(name="identify_flutter_build", description="Flutter AOT snapshot fingerprint.")
    def identify_flutter_build(path: str | None = None) -> dict[str, Any]:
        return _analysis(session, "identify_flutter_build", path, {})

    @server.tool(name="evidence_export", description="Export the session Evidence bundle.")
    def evidence_export(path: str) -> dict[str, Any]:
        bundle = session.export_bundle()
        Path(path).write_text(json.dumps(bundle, indent=2), encoding="utf-8")
        return {"path": path, "record_count": len(bundle.get("records", []))}

    @server.tool(name="evidence_import", description="Import an Evidence bundle file.")
    def evidence_import(path: str) -> dict[str, Any]:
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as cause:
            raise ToolError(
                json.dumps({"error": {"code": "INVALID_INPUT", "message": str(cause)}})
            ) from cause
        imported = session.import_bundle(payload)
        if not imported.ok:
            raise ToolError(_error_payload(imported.error))
        return {"imported": True, "delta": imported.value.__dict__}

    @server.tool(
        name="inspect_analysis_view", description="Summarize a saved Evidence record or bundle."
    )
    def inspect_analysis_view(
        source: str, view: str = "summary", offset: int = 0, limit: int = 64
    ) -> dict[str, Any]:
        projected = load_view(source, view, offset=offset, limit=limit)
        if not projected.ok:
            raise ToolError(_error_payload(projected.error))
        return projected.value

    @server.tool(name="inspect_with_objdump", description="File and section headers via objdump.")
    def inspect_with_objdump(path: str | None = None) -> dict[str, Any]:
        return _analysis(session, "inspect_with_objdump", path, {})

    @server.tool(name="instructions", description="Disassembly instructions.")
    def instructions(
        path: str | None = None,
        address: str = "entry0",
        count: int = 64,
        limit: int = 200,
        start: str | None = None,
        stop: str | None = None,
    ) -> dict[str, Any]:
        return _analysis(
            session,
            "instructions",
            path,
            {"address": address, "count": count, "limit": limit, "start": start, "stop": stop},
        )

    @server.tool(name="analyze", description="Provider overview analysis.")
    def analyze(path: str | None = None) -> dict[str, Any]:
        return _analysis(session, "analyze", path, {})

    @server.tool(name="function", description="List or select functions.")
    def function(
        path: str | None = None, function: str = "main", limit: int = 200
    ) -> dict[str, Any]:
        return _analysis(session, "function", path, {"function": function, "limit": limit})

    @server.tool(name="decompile", description="Pseudocode for a function.")
    def decompile(path: str | None = None, function: str = "main") -> dict[str, Any]:
        return _analysis(session, "decompile", path, {"function": function})

    @server.tool(name="search", description="Search within the target.")
    def search(path: str | None = None, query: str = "", limit: int = 100) -> dict[str, Any]:
        return _analysis(session, "search", path, {"query": query, "limit": limit})

    @server.tool(name="xrefs", description="Cross-references to an address or function.")
    def xrefs(
        path: str | None = None, address: str | None = None, function: str = "main"
    ) -> dict[str, Any]:
        return _analysis(session, "xrefs", path, {"address": address, "function": function})

    @server.tool(name="inspect_wasm_artifact", description="WASM validation, sections and WAT.")
    def inspect_wasm_artifact(path: str | None = None) -> dict[str, Any]:
        return _analysis(session, "inspect_wasm_artifact", path, {})

    @server.tool(name="inspect_evm_interface", description="EVM dispatch selectors.")
    def inspect_evm_interface(path: str | None = None) -> dict[str, Any]:
        return _analysis(session, "inspect_evm_interface", path, {})

    @server.tool(name="inspect_pcap_capture", description="Saved capture hierarchy and endpoints.")
    def inspect_pcap_capture(path: str | None = None) -> dict[str, Any]:
        return _analysis(session, "inspect_pcap_capture", path, {})

    @server.tool(name="inspect_firmware_regions", description="Firmware regions via binwalk.")
    def inspect_firmware_regions(path: str | None = None) -> dict[str, Any]:
        return _analysis(session, "inspect_firmware_regions", path, {})

    @server.tool(name="import_reference_source", description="Inventory a local source tree.")
    def import_reference_source(path: str | None = None) -> dict[str, Any]:
        return _analysis(session, "import_reference_source", path, {})

    @server.tool(name="inspect_plist", description="Property list (XML/binary) projection.")
    def inspect_plist(path: str | None = None) -> dict[str, Any]:
        return _analysis(session, "inspect_plist", path, {})

    @server.tool(name="compare_evidence", description="Compare two saved Evidence records.")
    def compare_evidence(left: str, right: str) -> dict[str, Any]:
        return compare_evidence_fn(_load_record(left), _load_record(right)).model_dump()

    @server.tool(name="capture_process", description="Run a command and capture bounded output.")
    def capture_process(
        command: list[str], timeout: float = 30.0, cwd: str | None = None
    ) -> dict[str, Any]:
        captured = capture_process_op(command, timeout=timeout, cwd=cwd)
        if not captured.ok:
            raise ToolError(_error_payload(captured.error))
        return captured.value

    @server.tool(name="doctor", description="Report provider and external-tool readiness.")
    def doctor() -> dict[str, Any]:
        return doctor_report(build_providers())

    @server.tool(name="inspect_managed_members", description="Managed member names and counts.")
    def inspect_managed_members(path: str | None = None) -> dict[str, Any]:
        return _analysis(session, "inspect_managed_members", path, {})

    @server.tool(
        name="disassemble_managed_method", description="Disassemble a managed method's IL."
    )
    def disassemble_managed_method(
        path: str | None = None, method: str = "", type: str | None = None
    ) -> dict[str, Any]:
        return _analysis(
            session, "disassemble_managed_method", path, {"method": method, "type": type}
        )

    @server.tool(name="inspect_network_capture", description="HAR/SAZ capture projection.")
    def inspect_network_capture(path: str | None = None) -> dict[str, Any]:
        return _analysis(session, "inspect_network_capture", path, {})

    @server.tool(name="inspect_harmony_package", description="HarmonyOS HAP package facts.")
    def inspect_harmony_package(path: str | None = None) -> dict[str, Any]:
        return _analysis(session, "inspect_harmony_package", path, {})

    @server.tool(name="analyze_javascript_application", description="JS/Electron module graph.")
    def analyze_javascript_application(path: str | None = None) -> dict[str, Any]:
        return _analysis(session, "analyze_javascript_application", path, {})

    @server.tool(name="inspect_keyed_archive", description="NSKeyedArchiver inventory.")
    def inspect_keyed_archive(path: str | None = None) -> dict[str, Any]:
        return _analysis(session, "inspect_keyed_archive", path, {})

    @server.tool(name="inspect_pe_resources", description="PE resource types and counts.")
    def inspect_pe_resources(path: str | None = None) -> dict[str, Any]:
        return _analysis(session, "inspect_pe_resources", path, {})

    @server.tool(
        name="inspect_asset_catalog", description="Apple asset catalog header and strings."
    )
    def inspect_asset_catalog(path: str | None = None) -> dict[str, Any]:
        return _analysis(session, "inspect_asset_catalog", path, {})

    @server.tool(name="capture_live_network", description="Capture live traffic via mitmproxy.")
    def capture_live_network(
        path: str | None = None, duration: float = 5.0, port: int = 8080
    ) -> dict[str, Any]:
        return _analysis(
            session, "capture_live_network", path, {"duration": duration, "port": port}
        )

    @server.tool(name="hopper_analyze", description="Hopper document overview via the bridge.")
    def hopper_analyze(path: str | None = None) -> dict[str, Any]:
        return _analysis(session, "hopper_analyze", path, {})

    @server.tool(name="hopper_function", description="Hopper function inventory via the bridge.")
    def hopper_function(
        path: str | None = None, function: str = "main", limit: int = 200
    ) -> dict[str, Any]:
        return _analysis(session, "hopper_function", path, {"function": function, "limit": limit})

    @server.tool(name="hopper_decompile", description="Hopper pseudocode via the bridge.")
    def hopper_decompile(path: str | None = None, function: str = "main") -> dict[str, Any]:
        return _analysis(session, "hopper_decompile", path, {"function": function})

    @server.tool(name="hopper_xrefs", description="Hopper references via the bridge.")
    def hopper_xrefs(
        path: str | None = None, address: str | None = None, function: str = "main"
    ) -> dict[str, Any]:
        return _analysis(session, "hopper_xrefs", path, {"address": address, "function": function})

    @server.tool(name="setup", description="Plan or write an MCP client registration.")
    def setup(path: str | None = None, overwrite: bool = False) -> dict[str, Any]:
        from ..application.setup import setup_plan, write_registration

        if path is None:
            return setup_plan()
        written = write_registration(path, overwrite=overwrite)
        if not written.ok:
            raise ToolError(_error_payload(written.error))
        return written.value

    @server.tool(name="update", description="Report the installed version and guidance.")
    def update() -> dict[str, Any]:
        from .. import __version__

        return {"current_version": __version__, "channel": "source"}

    return server


def _load_record(path: str) -> Any:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    parsed = parse_evidence(payload)
    if not parsed.ok:
        raise ToolError(
            _error_payload(
                AnalysisInputError(operation="compare_evidence", message=parsed.error.message)
            )
        )
    return parsed.value


def run_mcp_server(session: BinarySession, config: AppConfig | None = None) -> None:
    server = build_mcp_server(session, config)
    server.run(transport="stdio")


__all__ = ["build_mcp_server", "run_mcp_server"]
