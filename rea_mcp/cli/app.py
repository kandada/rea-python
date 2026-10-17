"""One-shot CLI adapter (typer). Each command uses a fresh session."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer

from ..application.analysis_view import load_view
from ..application.diagnostics import doctor_report
from ..application.process_capture import capture_process as capture_process_op
from ..application.session import BinarySession
from ..composition.factories import build_providers, create_binary_session
from ..config.settings import AppConfig
from ..domain.analysis_error import AnalysisInputError
from ..domain.comparison import compare_evidence as compare_evidence_fn
from ..domain.evidence import parse_evidence
from .output import emit_json, fail

app = typer.Typer(
    name="rea-mcp",
    help="Reverse engineer anything from your terminal, with evidence.",
    no_args_is_help=True,
    add_completion=False,
)


@app.callback(invoke_without_command=True)
def _global_options(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", help="Show version and exit."),
) -> None:
    """Global options shared by every command."""

    if version:
        from .. import __version__

        typer.echo(__version__)
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()


def _session() -> tuple[BinarySession, AppConfig]:
    config = AppConfig()
    return create_binary_session(config), config


def _run(operation: str, path: str, provider: str | None, parameters: dict[str, Any]) -> None:
    session, _config = _session()
    opened = session.open(path, provider_id=provider)
    if not opened.ok:
        fail(opened.error)
    result = session.execute(operation, parameters)
    if not result.ok:
        fail(result.error)
    emit_json(result.value.model_dump())


@app.command("inspect-binary-layout")
def inspect_binary_layout(
    path: str = typer.Argument(..., help="Target ELF/PE/Mach-O path."),
    provider: str | None = typer.Option(None, "--provider", help="Explicit provider id."),
) -> None:
    """Sections, segments, symbols and mitigation candidates."""
    _run("inspect_binary_layout", path, provider, {})


@app.command("inspect-go-binary")
def inspect_go_binary(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Embedded Go compiler version, modules and build settings."""
    _run("inspect_go_binary", path, provider, {})


@app.command("inspect-rust-binary")
def inspect_rust_binary(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """cargo-auditable dependency inventory."""
    _run("inspect_rust_binary", path, provider, {})


@app.command("inspect-managed-artifact")
def inspect_managed_artifact(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Static .NET/CLI metadata identity and table counts."""
    _run("inspect_managed_artifact", path, provider, {})


@app.command("inspect-sqlite-database")
def inspect_sqlite_database(
    path: str = typer.Argument(...),
    table: str | None = typer.Option(None, "--table"),
    row_limit: int = typer.Option(20, "--row-limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Tables, columns, indexes, views and triggers."""
    _run("inspect_sqlite_database", path, provider, {"table": table, "row_limit": row_limit})


@app.command("inspect-artifact")
def inspect_artifact(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """File inventory and digests for zip/apk/asar/tar/directory."""
    _run("inspect_artifact", path, provider, {})


@app.command("inspect-android-package")
def inspect_android_package(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """APK inventory, DEX facts and manifest package facts."""
    _run("inspect_android_package", path, provider, {})


@app.command("identify-flutter-build")
def identify_flutter_build(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Flutter AOT snapshot fingerprint per ABI."""
    _run("identify_flutter_build", path, provider, {})


@app.command("inspect-wasm-artifact")
def inspect_wasm_artifact(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """WASM validation, sections and (with WABT) decoded WAT."""
    _run("inspect_wasm_artifact", path, provider, {})


@app.command("inspect-evm-interface")
def inspect_evm_interface(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """EVM dispatch selectors via evmole (optional)."""
    _run("inspect_evm_interface", path, provider, {})


@app.command("inspect-pcap-capture")
def inspect_pcap_capture(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Saved capture protocol hierarchy and endpoints (tshark)."""
    _run("inspect_pcap_capture", path, provider, {})


@app.command("inspect-firmware-regions")
def inspect_firmware_regions(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Firmware regions via binwalk (caller-supplied)."""
    _run("inspect_firmware_regions", path, provider, {})


@app.command("import-reference-source")
def import_reference_source(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Inventory a local source tree (files, sizes, digests, languages)."""
    _run("import_reference_source", path, provider, {})


@app.command("inspect-plist")
def inspect_plist(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Property list (XML/binary) top-level projection."""
    _run("inspect_plist", path, provider, {})


@app.command("inspect-with-objdump")
def inspect_with_objdump(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """File and section headers via GNU objdump."""
    _run("inspect_with_objdump", path, provider, {})


@app.command("instructions")
def instructions(
    path: str = typer.Argument(...),
    address: str = typer.Option("entry0", "--address"),
    count: int = typer.Option(64, "--count"),
    limit: int = typer.Option(200, "--limit"),
    start: str | None = typer.Option(None, "--start"),
    stop: str | None = typer.Option(None, "--stop"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Disassembly instructions."""
    _run(
        "instructions",
        path,
        provider,
        {"address": address, "count": count, "limit": limit, "start": start, "stop": stop},
    )


@app.command("analyze")
def analyze(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Provider overview analysis."""
    _run("analyze", path, provider, {})


@app.command("function")
def function(
    path: str = typer.Argument(...),
    function: str = typer.Option("main", "--function"),
    limit: int = typer.Option(200, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """List or select functions."""
    _run("function", path, provider, {"function": function, "limit": limit})


@app.command("decompile")
def decompile(
    path: str = typer.Argument(...),
    function: str = typer.Option("main", "--function"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Pseudocode for a function."""
    _run("decompile", path, provider, {"function": function})


@app.command("search")
def search(
    path: str = typer.Argument(...),
    query: str = typer.Argument(...),
    limit: int = typer.Option(100, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Search within the target."""
    _run("search", path, provider, {"query": query, "limit": limit})


@app.command("xrefs")
def xrefs(
    path: str = typer.Argument(...),
    address: str | None = typer.Option(None, "--address"),
    function: str = typer.Option("main", "--function"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Cross-references to an address or function."""
    _run("xrefs", path, provider, {"address": address, "function": function})


@app.command("inspect-managed-members")
def inspect_managed_members(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Managed assembly member names and counts."""
    _run("inspect_managed_members", path, provider, {})


@app.command("disassemble-managed-method")
def disassemble_managed_method(
    path: str = typer.Argument(...),
    method: str = typer.Option(..., "--method"),
    type: str | None = typer.Option(None, "--type"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Disassemble one managed method's IL body."""
    _run("disassemble_managed_method", path, provider, {"method": method, "type": type})


@app.command("inspect-network-capture")
def inspect_network_capture(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """HAR/SAZ capture requests, hosts and status."""
    _run("inspect_network_capture", path, provider, {})


@app.command("inspect-harmony-package")
def inspect_harmony_package(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """HarmonyOS HAP package facts."""
    _run("inspect_harmony_package", path, provider, {})


@app.command("analyze-javascript-application")
def analyze_javascript_application(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """JavaScript/Electron module graph."""
    _run("analyze_javascript_application", path, provider, {})


@app.command("inspect-keyed-archive")
def inspect_keyed_archive(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """NSKeyedArchiver class and object inventory."""
    _run("inspect_keyed_archive", path, provider, {})


@app.command("inspect-pe-resources")
def inspect_pe_resources(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """PE resource types and counts."""
    _run("inspect_pe_resources", path, provider, {})


@app.command("inspect-asset-catalog")
def inspect_asset_catalog(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Apple asset catalog (Assets.car) header and embedded strings."""
    _run("inspect_asset_catalog", path, provider, {})


@app.command("capture-live-network")
def capture_live_network(
    path: str = typer.Argument(..., help="Unused placeholder target path."),
    duration: float = typer.Option(5.0, "--duration"),
    port: int = typer.Option(8080, "--port"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Capture live HTTP(S) traffic through a caller-supplied mitmproxy."""
    _run("capture_live_network", path, provider, {"duration": duration, "port": port})


@app.command("hopper-analyze")
def hopper_analyze(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Hopper document overview via the running bridge."""
    _run("hopper_analyze", path, provider, {})


@app.command("hopper-function")
def hopper_function(
    path: str = typer.Argument(...),
    limit: int = typer.Option(200, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Hopper function inventory via the running bridge."""
    _run("hopper_function", path, provider, {"limit": limit})


@app.command("hopper-decompile")
def hopper_decompile(
    path: str = typer.Argument(...),
    function: str = typer.Option("main", "--function"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Hopper pseudocode via the running bridge."""
    _run("hopper_decompile", path, provider, {"function": function})


@app.command("hopper-xrefs")
def hopper_xrefs(
    path: str = typer.Argument(...),
    address: str | None = typer.Option(None, "--address"),
    function: str = typer.Option("main", "--function"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Hopper references via the running bridge."""
    _run("hopper_xrefs", path, provider, {"address": address, "function": function})


@app.command("setup")
def setup(
    write: str | None = typer.Option(None, "--write", help="Client config path to write."),
    overwrite: bool = typer.Option(False, "--overwrite"),
) -> None:
    """Plan or write an MCP client registration for the REA-Python server."""
    from ..application.setup import setup_plan, write_registration

    if write is None:
        emit_json(setup_plan())
        return
    written = write_registration(write, overwrite=overwrite)
    if not written.ok:
        fail(written.error)
    emit_json(written.value)


@app.command("update")
def update() -> None:
    """Report the installed version and update guidance."""
    from .. import __version__

    emit_json({"current_version": __version__, "channel": "source"})


@app.command("providers")
def providers() -> None:
    """List configured providers and their operations."""
    session, _config = _session()
    emit_json({"providers": session.providers()})


@app.command("capabilities")
def capabilities() -> None:
    """Alias for providers, including the declared operation set."""
    session, _config = _session()
    emit_json({"providers": session.providers(), "operations": _declared_operations(session)})


@app.command("inspect-analysis-view")
def inspect_analysis_view(
    source: str = typer.Argument(..., help="Saved Evidence record or bundle JSON."),
    view: str = typer.Option("summary", "--view", help="summary | record | page"),
    offset: int = typer.Option(0, "--offset"),
    limit: int = typer.Option(64, "--limit"),
) -> None:
    """Project a saved Evidence record or bundle (summary, record, or page)."""
    projected = load_view(source, view, offset=offset, limit=limit)
    if not projected.ok:
        fail(projected.error)
    emit_json(projected.value)


@app.command("evidence-export")
def evidence_export(
    source: str = typer.Argument(..., help="Bundle JSON to validate and canonicalize."),
    destination: str | None = typer.Option(None, "--out"),
) -> None:
    """Validate a bundle and print (or write) its canonical projection."""
    payload = _read_json(source)
    if destination is None:
        emit_json(payload)
    else:
        Path(destination).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        emit_json({"written": destination})


@app.command("evidence-import")
def evidence_import(source: str = typer.Argument(...)) -> None:
    """Validate a bundle and report a summary."""
    payload = _read_json(source)
    if "records" not in payload:
        fail(AnalysisInputError(operation="evidence_import", message="Not an Evidence bundle"))
    emit_json({"valid": True, "record_count": len(payload["records"])})


@app.command("mcp")
def mcp() -> None:
    """Run the MCP server over stdio."""
    from ..server.app import run_mcp_server

    session, config = _session()
    run_mcp_server(session, config)


@app.command("compare")
def compare(
    left: str = typer.Argument(..., help="Left Evidence record JSON."),
    right: str = typer.Argument(..., help="Right Evidence record JSON."),
) -> None:
    """Compare two saved Evidence records."""
    emit_json(compare_evidence_fn(_load_record(left), _load_record(right)).model_dump())


@app.command("capture-process")
def capture_process(
    command: list[str] = typer.Argument(..., help="Command and arguments to run."),
    timeout: float = typer.Option(30.0, "--timeout"),
    cwd: str | None = typer.Option(None, "--cwd"),
) -> None:
    """Run a command and capture bounded stdout/stderr, exit code and timeout."""
    captured = capture_process_op(command, timeout=timeout, cwd=cwd)
    if not captured.ok:
        fail(captured.error)
    emit_json(captured.value)


@app.command("doctor")
def doctor() -> None:
    """Report provider and external-tool readiness."""
    emit_json(doctor_report(build_providers()))


def _declared_operations(session: BinarySession) -> list[str]:
    operations: set[str] = set()
    for provider in session.providers():
        operations.update(provider["operations"])
    return sorted(operations)


def _read_json(source: str) -> Any:
    path = Path(source)
    if not path.is_file():
        fail(AnalysisInputError(operation="read_json", message=f"Not found: {source}"))
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as cause:
        fail(AnalysisInputError(operation="read_json", message=str(cause)))


def _load_record(source: str) -> Any:
    parsed = parse_evidence(_read_json(source))
    if not parsed.ok:
        fail(parsed.error)
    return parsed.value


__all__ = ["app"]
