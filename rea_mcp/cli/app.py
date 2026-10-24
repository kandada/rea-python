"""One-shot CLI adapter (typer). Each command uses a fresh session."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, cast

import typer

from ..application.analysis_view import load_view
from ..application.diagnostics import doctor_report
from ..application.process_capture import capture_process as capture_process_op
from ..application.session import BinarySession
from ..composition.factories import build_providers, create_binary_session
from ..config.settings import AppConfig
from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.comparison import compare_evidence as compare_evidence_fn
from ..domain.evidence import parse_evidence
from .output import emit_json, fail, set_output_budget

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
    output_budget: int = typer.Option(
        0,
        "--output-budget",
        help="Write oversized JSON to a file and print a summary (bytes; 0 disables).",
    ),
) -> None:
    """Global options shared by every command."""

    set_output_budget(output_budget or int(os.environ.get("REA_CLI_MAX_RESPONSE_BYTES", "0") or 0))
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


def _run(
    operation: str,
    path: str,
    provider: str | None,
    parameters: dict[str, Any],
    format_hint: str | None = None,
) -> None:
    session, _config = _session()
    opened = session.open(path, provider_id=provider, format_hint=format_hint)  # type: ignore[arg-type]
    if not opened.ok:
        fail(opened.error)
    result = session.execute(operation, parameters)
    if not result.ok:
        fail(result.error)
    emit_json(result.value.model_dump())


def _compat(func) -> None:  # type: ignore[no-untyped-def]
    try:
        emit_json(func())
    except AnalysisError as cause:
        fail(cause)
    except (OSError, ValueError, KeyError) as cause:
        fail(AnalysisInputError(operation="cli", message=str(cause)))


def _run_session(path: str, provider: str | None, func):  # type: ignore[no-untyped-def]
    session, _config = _session()
    opened = session.open(path, provider_id=provider)
    if not opened.ok:
        fail(opened.error)
    emit_json(func(session))


def _run_runtime(operation: str, subject: str, parameters: dict[str, Any]) -> None:
    import hashlib

    from ..domain.binary_target import BinaryTarget

    target = BinaryTarget(
        path=subject,
        sha256=hashlib.sha256(subject.encode("utf-8")).hexdigest(),
        kind="unknown",
        format="unknown",
    )
    for provider in build_providers():
        if any(capability.operation == operation for capability in provider.capabilities()):
            result = provider.analyze(operation, target, parameters, None)
            if not result.ok:
                fail(result.error)
            emit_json(result.value.result)
            return
    fail(AnalysisInputError(operation=operation, message=f"no provider supports {operation}"))


@app.command("inspect-byte-entropy")
def inspect_byte_entropy(
    path: str = typer.Argument(...),
    block_size: int = typer.Option(4096, "--block-size"),
    offset: int = typer.Option(0, "--offset"),
    length: int | None = typer.Option(None, "--length"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """File and block byte entropy."""
    _run(
        "inspect_byte_entropy",
        path,
        provider,
        {"block_size": block_size, "offset": offset, "length": length},
    )


@app.command("inspect-binary-layout")
def inspect_binary_layout(
    path: str = typer.Argument(..., help="Target ELF/PE/Mach-O path."),
    provider: str | None = typer.Option(None, "--provider", help="Explicit provider id."),
) -> None:
    """Sections, segments, symbols and mitigation candidates."""
    _run("inspect_binary_layout", path, provider, {})


@app.command("inspect-elf-notes")
def inspect_elf_notes(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """ELF PT_NOTE and SHT_NOTE tables."""
    _run("inspect_elf_notes", path, provider, {})


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
    detail: str = typer.Option("complete", "--detail", help="complete or summary."),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Static .NET/CLI metadata identity and table counts."""
    _run("inspect_managed_artifact", path, provider, {"detail": detail})


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
    offset: int = typer.Option(0, "--offset"),
    limit: int = typer.Option(500, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """File inventory and digests for zip/apk/asar/tar/directory."""
    _run("inspect_artifact", path, provider, {"offset": offset, "limit": limit})


@app.command("inspect-android-package")
def inspect_android_package(
    path: str = typer.Argument(...),
    offset: int = typer.Option(0, "--offset"),
    limit: int = typer.Option(200, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """APK inventory, DEX facts and manifest package facts."""
    _run("inspect_android_package", path, provider, {"offset": offset, "limit": limit})


@app.command("identify-flutter-build")
def identify_flutter_build(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Flutter AOT snapshot fingerprint per ABI."""
    _run("identify_flutter_build", path, provider, {})


@app.command("inspect-apk-signature")
def inspect_apk_signature(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """APK v1/v2/v3 signature declarations."""
    _run("inspect_apk_signature", path, provider, {})


@app.command("inspect-il2cpp-metadata")
def inspect_il2cpp_metadata(
    path: str = typer.Argument(...),
    binary_path: str | None = typer.Option(None, "--binary"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Unity IL2CPP global-metadata tables and optional native symbol link."""
    _run(
        "inspect_il2cpp_metadata",
        path,
        provider,
        {"binary_path": binary_path},
    )


@app.command("inspect-desktop-application")
def inspect_desktop_application(
    path: str = typer.Argument(...),
    detail: str = typer.Option("complete", "--detail", help="complete or summary."),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Desktop application directory triage."""
    _run("inspect_desktop_application", path, provider, {"detail": detail})


@app.command("inspect-gpu-code-objects")
def inspect_gpu_code_objects(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Static GPU code-object discovery."""
    _run("inspect_gpu_code_objects", path, provider, {})


@app.command("inspect-python-pyc")
def inspect_python_pyc(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """CPython .pyc header and marshalled code objects."""
    _run("inspect_python_pyc", path, provider, {})


@app.command("inspect-model-artifact")
def inspect_model_artifact(
    path: str = typer.Argument(...),
    hash: str = typer.Option("header", "--hash", help="header or full."),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """GGUF/safetensors header inventory."""
    _run("inspect_model_artifact", path, provider, {"hash": hash})


@app.command("inspect-erlang-beam")
def inspect_erlang_beam(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Erlang BEAM IFF chunks, atoms, exports and imports."""
    _run("inspect_erlang_beam", path, provider, {})


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


@app.command("decompile-managed-csharp")
def decompile_managed_csharp(
    path: str = typer.Argument(...),
    type_name: str = typer.Option(..., "--type"),
    method: str | None = typer.Option(None, "--method"),
    offset: int = typer.Option(0, "--offset"),
    limit: int = typer.Option(500, "--limit"),
    max_bytes: int = typer.Option(64000, "--max-bytes"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Optional C# decompilation through ilspycmd."""
    _run(
        "decompile_managed_csharp",
        path,
        provider,
        {
            "type": type_name,
            "method": method,
            "offset": offset,
            "limit": limit,
            "max_bytes": max_bytes,
        },
    )


@app.command("decompile")
def decompile(
    path: str = typer.Argument(...),
    function: str = typer.Option("main", "--function"),
    max_bytes: int = typer.Option(64000, "--max-bytes"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Pseudocode for a function."""
    _run("decompile", path, provider, {"function": function, "max_bytes": max_bytes})


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
    raw_image: bool = typer.Option(False, "--raw-image"),
    target: str | None = typer.Option(None, "--target"),
    base: str | None = typer.Option(None, "--base"),
    entry: str | None = typer.Option(None, "--entry"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Cross-references to an address or function."""
    _run(
        "xrefs",
        path,
        provider,
        {
            "address": address,
            "function": function,
            "target": target,
            "base": base,
            "entry": entry,
        },
        format_hint="raw-binary" if raw_image else None,
    )


@app.command("inspect-managed-members")
def inspect_managed_members(
    path: str = typer.Argument(...),
    offset: int = typer.Option(0, "--offset", help="Type page offset."),
    limit: int = typer.Option(256, "--limit", help="Type page size."),
    method_offset: int = typer.Option(0, "--method-offset"),
    method_limit: int = typer.Option(64, "--method-limit"),
    type_names: list[str] = typer.Option([], "--type", help="Exact declaring type full name."),
    detail: str = typer.Option("complete", "--detail", help="complete or summary."),
    include_bodies: bool | None = typer.Option(None, "--bodies/--no-bodies"),
    evidence_bundle: str | None = typer.Option(
        None, "--evidence-bundle", help="Write the complete parent Evidence to this new file."
    ),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Managed assembly members, signatures, fields and CIL anchors."""
    if detail not in ("complete", "summary"):
        fail(
            AnalysisInputError(
                operation="inspect_managed_members", message="detail must be complete or summary"
            )
        )
    if detail == "summary" and evidence_bundle is None:
        fail(
            AnalysisInputError(
                operation="inspect_managed_members",
                message="summary delivery requires --evidence-bundle so the complete parent Evidence remains available",
            )
        )
    session, _config = _session()
    opened = session.open(path, provider_id=provider)
    if not opened.ok:
        fail(opened.error)
    result = session.execute(
        "inspect_managed_members",
        {
            "offset": offset,
            "limit": limit,
            "method_offset": method_offset,
            "method_limit": method_limit,
            "type_names": list(type_names) or None,
            "detail": "complete",
            "include_bodies": include_bodies,
        },
    )
    if not result.ok:
        fail(result.error)
    payload = result.value.model_dump()
    receipt = None
    if evidence_bundle is not None:
        destination = Path(evidence_bundle)
        if destination.exists():
            fail(
                AnalysisInputError(
                    operation="inspect_managed_members",
                    message=f"evidence bundle already exists: {destination}",
                )
            )
        if not destination.parent.is_dir():
            fail(
                AnalysisInputError(
                    operation="inspect_managed_members",
                    message=f"evidence bundle parent does not exist: {destination.parent}",
                )
            )
        text = json.dumps(session.export_bundle(), indent=2, ensure_ascii=False)
        try:
            destination.write_text(text, encoding="utf-8")
        except OSError as cause:
            fail(AnalysisInputError(operation="inspect_managed_members", message=str(cause)))
        receipt = {"path": str(destination), "bytes": len(text.encode("utf-8"))}
    if detail == "summary":
        from ..providers.formats.managed_inspection import summarize_managed_inspection

        summary = summarize_managed_inspection(payload.get("normalized_result") or {})
        summary["evidence_id"] = payload.get("evidence_id")
        emit_json(
            {
                "summary": summary,
                "evidence_id": payload.get("evidence_id"),
                "evidence_bundle": receipt,
            }
        )
    elif receipt is not None:
        emit_json({"evidence": payload, "evidence_bundle": receipt})
    else:
        emit_json(payload)


@app.command("disassemble-managed-method")
def disassemble_managed_method(
    path: str = typer.Argument(...),
    method: str = typer.Option("", "--method"),
    type: str | None = typer.Option(None, "--type"),
    token: str | None = typer.Option(None, "--token"),
    rva: str | None = typer.Option(None, "--rva"),
    signature: str | None = typer.Option(None, "--signature"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Disassemble one managed method's IL body."""
    _run(
        "disassemble_managed_method",
        path,
        provider,
        {"method": method, "type": type, "token": token, "rva": rva, "signature": signature},
    )


@app.command("inspect-network-capture")
def inspect_network_capture(
    path: str = typer.Argument(...),
    offset: int = typer.Option(0, "--offset"),
    limit: int = typer.Option(100, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """HAR/SAZ capture requests, hosts and status."""
    _run("inspect_network_capture", path, provider, {"offset": offset, "limit": limit})


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
    module_offset: int = typer.Option(0, "--module-offset"),
    module_limit: int = typer.Option(500, "--module-limit"),
    edge_offset: int = typer.Option(0, "--edge-offset"),
    edge_limit: int = typer.Option(500, "--edge-limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """JavaScript/Electron module graph."""
    _run(
        "analyze_javascript_application",
        path,
        provider,
        {
            "module_offset": module_offset,
            "module_limit": module_limit,
            "edge_offset": edge_offset,
            "edge_limit": edge_limit,
        },
    )


@app.command("inspect-keyed-archive")
def inspect_keyed_archive(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """NSKeyedArchiver class and object inventory."""
    _run("inspect_keyed_archive", path, provider, {})


@app.command("inspect-pe-certificates")
def inspect_pe_certificates(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """PE Authenticode certificate table entries."""
    _run("inspect_pe_certificates", path, provider, {})


@app.command("inspect-native-exports")
def inspect_native_exports(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """PE/ELF export names, ordinals and addresses."""
    _run("inspect_native_exports", path, provider, {})


@app.command("inspect-javascript-webmcp")
def inspect_javascript_webmcp(
    path: str = typer.Argument(...),
    offset: int = typer.Option(0, "--offset"),
    limit: int = typer.Option(200, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Static JavaScript WebMCP declaration candidates."""
    _run(
        "inspect_javascript_webmcp",
        path,
        provider,
        {"offset": offset, "limit": limit},
    )


@app.command("inspect-javascript-source-maps")
def inspect_javascript_source_maps(
    path: str = typer.Argument(...),
    offset: int = typer.Option(0, "--offset"),
    limit: int = typer.Option(200, "--limit"),
    line: int | None = typer.Option(None, "--line"),
    column: int | None = typer.Option(None, "--column"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Static JavaScript source-map inventory and optional position lookup."""
    _run(
        "inspect_javascript_source_maps",
        path,
        provider,
        {"offset": offset, "limit": limit, "line": line, "column": column},
    )


@app.command("inspect-javascript-routes")
def inspect_javascript_routes(
    path: str = typer.Argument(...),
    offset: int = typer.Option(0, "--offset"),
    limit: int = typer.Option(200, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Static JavaScript route candidates."""
    _run(
        "inspect_javascript_routes",
        path,
        provider,
        {"offset": offset, "limit": limit},
    )


@app.command("inspect-javascript-dataflow")
def inspect_javascript_dataflow(
    path: str = typer.Argument(...),
    offset: int = typer.Option(0, "--offset"),
    limit: int = typer.Option(200, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Static JavaScript storage/DOM source-to-sink flows."""
    _run(
        "inspect_javascript_dataflow",
        path,
        provider,
        {"offset": offset, "limit": limit},
    )


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
    write_all: str | None = typer.Option(
        None, "--write-all", help="Sandbox base dir; write every known client config under it."
    ),
    install_skill_dir: str | None = typer.Option(
        None, "--install-skill", help="Directory to install the agent skill into."
    ),
    overwrite: bool = typer.Option(False, "--overwrite"),
) -> None:
    """Plan or write an MCP client registration, or install the agent skill."""
    from ..application.setup import (
        install_skill,
        setup_plan,
        write_all_registrations,
        write_registration,
    )

    if write_all is not None:
        applied = write_all_registrations(write_all, overwrite=overwrite)
        if not applied.ok:
            fail(applied.error)
        emit_json(applied.value)
        return
    if install_skill_dir is not None:
        installed = install_skill(install_skill_dir)
        if not installed.ok:
            fail(installed.error)
        emit_json(installed.value)
        return
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


@app.command("record-unknown")
def record_unknown(
    path: str = typer.Argument(...),
    question: str = typer.Option(..., "--question"),
    domain: str = typer.Option(..., "--domain"),
    severity: str = typer.Option("medium", "--severity"),
    required_authority: str | None = typer.Option(None, "--required-authority"),
    required_confidence: str = typer.Option("observed", "--required-confidence"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Record an unresolved investigation question."""
    session, _config = _session()
    opened = session.open(path, provider_id=provider)
    if not opened.ok:
        fail(opened.error)
    result = session.record_unknown(
        question,
        domain,
        severity=severity,
        required_authority=required_authority,
        required_confidence=required_confidence,
    )
    if not result.ok:
        fail(result.error)
    emit_json(result.value)


@app.command("update-unknown")
def update_unknown(
    path: str = typer.Argument(...),
    unknown_id: str = typer.Option(..., "--unknown-id"),
    status: str = typer.Option(..., "--status"),
    severity: str | None = typer.Option(None, "--severity"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Update an unknown's status."""
    session, _config = _session()
    opened = session.open(path, provider_id=provider)
    if not opened.ok:
        fail(opened.error)
    result = session.update_unknown(unknown_id, status, severity=severity)
    if not result.ok:
        fail(result.error)
    emit_json(result.value)


@app.command("list-unknowns")
def list_unknowns() -> None:
    """List recorded unknowns (current revisions)."""
    session, _config = _session()
    emit_json({"unknowns": session.list_unknowns()})


@app.command("snapshot-export")
def snapshot_export(
    path: str = typer.Argument(...),
    out: str = typer.Argument(...),
    overwrite: bool = typer.Option(False, "--overwrite"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Open a target and export an analysis snapshot to a file."""
    session, _config = _session()
    opened = session.open(path, provider_id=provider)
    if not opened.ok:
        fail(opened.error)
    result = session.write_snapshot(out, overwrite=overwrite)
    if not result.ok:
        fail(result.error)
    emit_json(result.value)


@app.command("snapshot-import")
def snapshot_import(
    path: str = typer.Argument(...),
    source: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Import a saved analysis snapshot for a target."""
    session, _config = _session()
    opened = session.open(path, provider_id=provider)
    if not opened.ok:
        fail(opened.error)
    payload = _read_json(source)
    result = session.import_snapshot(payload)
    if not result.ok:
        fail(result.error)
    emit_json({"imported": True, "source": source})


@app.command("inspect-electron-fuses")
def inspect_electron_fuses(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Electron fuse-wire security posture."""
    _run("inspect_electron_fuses", path, provider, {})


@app.command("inspect-entitlements")
def inspect_entitlements(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Entitlements plist key/value inventory."""
    _run("inspect_entitlements", path, provider, {})


@app.command("compare-network-captures")
def compare_network_captures(
    left: str = typer.Argument(...),
    right: str = typer.Argument(...),
) -> None:
    """Compare two HAR/SAZ captures by request set."""
    from ..providers.network_capture import compare_capture_files

    compared = compare_capture_files(left, right)
    if not compared.ok:
        fail(compared.error)
    emit_json(compared.value)


@app.command("build-reconstruction-obligation-ledger")
def build_reconstruction_obligation_ledger(source: str = typer.Argument(...)) -> None:
    """Build a reconstruction obligation ledger from a JSON list of obligations."""
    from ..domain.reconstruction import Obligation, build_ledger

    payload = _read_json(source)
    items = payload.get("obligations", payload) if isinstance(payload, dict) else payload
    try:
        obligations = [Obligation.model_validate(item) for item in items]
    except Exception as cause:
        fail(
            AnalysisInputError(
                operation="build_reconstruction_obligation_ledger", message=str(cause)
            )
        )
    emit_json(build_ledger(obligations).model_dump())


@app.command("evaluate-reconstruction-coverage")
def evaluate_reconstruction_coverage(source: str = typer.Argument(...)) -> None:
    """Evaluate coverage/gaps from a reconstruction ledger JSON."""
    from ..domain.reconstruction import ReconstructionLedger, evaluate_coverage

    try:
        ledger = ReconstructionLedger.model_validate(_read_json(source))
    except Exception as cause:
        fail(AnalysisInputError(operation="evaluate_reconstruction_coverage", message=str(cause)))
    emit_json(evaluate_coverage(ledger))


@app.command("compare-web-captures")
def compare_web_captures(left: str = typer.Argument(...), right: str = typer.Argument(...)) -> None:
    """Compare two web network captures by request set."""
    from ..providers.network_capture import compare_capture_files

    compared = compare_capture_files(left, right)
    if not compared.ok:
        fail(compared.error)
    emit_json(compared.value)


@app.command("compare-managed-members")
def compare_managed_members(
    left: str = typer.Argument(...), right: str = typer.Argument(...)
) -> None:
    """Compare the member sets of two managed assemblies."""
    from ..providers.dotnet import compare_managed_members as _compare

    compared = _compare(left, right)
    if not compared.ok:
        fail(compared.error)
    emit_json(compared.value)


@app.command("inspect-interface-builder")
def inspect_interface_builder(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Compiled Interface Builder archive inventory."""
    _run("inspect_interface_builder", path, provider, {})


@app.command("inspect-signal-capture")
def inspect_signal_capture(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """VCD signal inventory."""
    _run("inspect_signal_capture", path, provider, {})


@app.command("decode-uart-capture")
def decode_uart_capture(
    path: str = typer.Argument(...),
    channel: str | None = typer.Option(None, "--channel"),
    baud: int = typer.Option(9600, "--baud"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Decode 8N1 UART from a VCD signal."""
    _run("decode_uart_capture", path, provider, {"channel": channel, "baud": baud})


@app.command("inspect-crash-dump")
def inspect_crash_dump(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Structured GDB/pwndbg crash-dump summary."""
    _run("inspect_crash_dump", path, provider, {})


@app.command("observe-web-page")
def observe_web_page(url: str = typer.Argument(...)) -> None:
    """Observe a page's title, final URL and script count via playwright."""
    _run_runtime("observe_web_page", url, {"url": url})


@app.command("inspect-cdp-targets")
def inspect_cdp_targets(
    endpoint: str | None = typer.Option(None, "--endpoint"),
) -> None:
    """List Chrome DevTools Protocol targets from a running runtime."""
    _run_runtime("inspect_cdp_targets", endpoint or "cdp", {"endpoint": endpoint})


@app.command("capture-cdp-network")
def capture_cdp_network(
    endpoint: str | None = typer.Option(None, "--endpoint"),
    duration: float = typer.Option(5.0, "--duration"),
    target_url: str | None = typer.Option(None, "--target-url"),
) -> None:
    """Capture CDP network request metadata for a bounded duration."""
    _run_runtime(
        "capture_cdp_network",
        endpoint or "cdp",
        {"endpoint": endpoint, "duration": duration, "target_url": target_url},
    )


@app.command("decode-android-resources")
def decode_android_resources(
    path: str = typer.Argument(...),
    include_strings: bool = typer.Option(True, "--include-strings/--no-include-strings"),
    string_tables_only: bool = typer.Option(False, "--string-tables-only"),
    locale: str | None = typer.Option(None, "--locale"),
    locales: list[str] = typer.Option([], "--locales"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Decode APK resources with apktool, optionally projecting string tables."""
    _run(
        "decode_android_resources",
        path,
        provider,
        {
            "include_strings": include_strings,
            "string_tables_only": string_tables_only,
            "locale": locale,
            "locales": list(locales) or None,
        },
    )


@app.command("decode-android-smali")
def decode_android_smali(
    path: str = typer.Argument(...), provider: str | None = typer.Option(None, "--provider")
) -> None:
    """Full apktool smali inventory."""
    _run("decode_android_smali", path, provider, {})


@app.command("decompile-android-apk")
def decompile_android_apk(
    path: str = typer.Argument(...),
    offset: int = typer.Option(0, "--offset"),
    limit: int = typer.Option(500, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Decompile an APK to Java with JADX."""
    _run("decompile_android_apk", path, provider, {"offset": offset, "limit": limit})


@app.command("decompile-android-class")
def decompile_android_class(
    path: str = typer.Argument(...),
    class_name: str = typer.Option(..., "--class"),
    offset: int = typer.Option(0, "--offset"),
    limit: int = typer.Option(500, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Decompile one class with JADX."""
    _run(
        "decompile_android_class",
        path,
        provider,
        {"class": class_name, "offset": offset, "limit": limit},
    )


@app.command("decode-signal-recording")
def decode_signal_recording(
    path: str = typer.Argument(...),
    decoder: str | None = typer.Option(None, "--decoder"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Decode a logic-signal recording with sigrok."""
    _run("decode_signal_recording", path, provider, {"decoder": decoder})


@app.command("kuna-decompile")
def kuna_decompile(
    path: str = typer.Argument(...),
    function: str | None = typer.Option(None, "--function"),
    max_bytes: int = typer.Option(64000, "--max-bytes"),
    raw_image: bool = typer.Option(False, "--raw-image"),
    target: str | None = typer.Option(None, "--target"),
    base: str | None = typer.Option(None, "--base"),
    entry: str | None = typer.Option(None, "--entry"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Decompile a function with Kuna."""
    _run(
        "kuna_decompile",
        path,
        provider,
        {
            "function": function,
            "max_bytes": max_bytes,
            "target": target,
            "base": base,
            "entry": entry,
        },
        format_hint="raw-binary" if raw_image else None,
    )


@app.command("ghidra-analyze")
def ghidra_analyze(
    path: str = typer.Argument(...),
    language: str | None = typer.Option(None, "--language"),
    compiler: str | None = typer.Option(None, "--compiler"),
    entry: str | None = typer.Option(None, "--entry"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Ghidra overview via pyhidra/pyghidra."""
    _run(
        "ghidra_analyze",
        path,
        provider,
        {"language": language, "compiler": compiler, "entry": entry},
    )


@app.command("ghidra-function")
def ghidra_function(
    path: str = typer.Argument(...),
    function: str = typer.Option("main", "--function"),
    limit: int = typer.Option(200, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Ghidra function inventory."""
    _run("ghidra_function", path, provider, {"function": function, "limit": limit})


@app.command("ghidra-decompile")
def ghidra_decompile(
    path: str = typer.Argument(...),
    function: str = typer.Option("main", "--function"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Ghidra pseudocode."""
    _run("ghidra_decompile", path, provider, {"function": function})


@app.command("ida-analyze")
def ida_analyze(
    path: str = typer.Argument(...), provider: str | None = typer.Option(None, "--provider")
) -> None:
    """IDA overview via the running service."""
    _run("ida_analyze", path, provider, {})


@app.command("ida-function")
def ida_function(
    path: str = typer.Argument(...),
    function: str = typer.Option("main", "--function"),
    limit: int = typer.Option(200, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """IDA function inventory."""
    _run("ida_function", path, provider, {"function": function, "limit": limit})


@app.command("ida-decompile")
def ida_decompile(
    path: str = typer.Argument(...),
    function: str = typer.Option("main", "--function"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """IDA pseudocode."""
    _run("ida_decompile", path, provider, {"function": function})


@app.command("ida-xrefs")
def ida_xrefs(
    path: str = typer.Argument(...),
    address: str | None = typer.Option(None, "--address"),
    function: str = typer.Option("main", "--function"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """IDA cross-references."""
    _run("ida_xrefs", path, provider, {"address": address, "function": function})


@app.command("jeb-analyze")
def jeb_analyze(
    path: str = typer.Argument(...), provider: str | None = typer.Option(None, "--provider")
) -> None:
    """JEB overview via the running service."""
    _run("jeb_analyze", path, provider, {})


@app.command("jeb-function")
def jeb_function(
    path: str = typer.Argument(...),
    function: str = typer.Option("main", "--function"),
    limit: int = typer.Option(200, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """JEB function inventory."""
    _run("jeb_function", path, provider, {"function": function, "limit": limit})


@app.command("jeb-decompile")
def jeb_decompile(
    path: str = typer.Argument(...),
    function: str = typer.Option("main", "--function"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """JEB pseudocode."""
    _run("jeb_decompile", path, provider, {"function": function})


@app.command("inspect-recorded-crash")
def inspect_recorded_crash(
    path: str = typer.Argument(...),
    executable: str = typer.Option(..., "--executable"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Registers/signal from a recorded core."""
    _run("inspect_recorded_crash", path, provider, {"executable": executable})


@app.command("list-adb-devices")
def list_adb_devices() -> None:
    """List attached ADB devices."""
    _run_runtime("list_adb_devices", "adb", {})


@app.command("list-adb-packages")
def list_adb_packages() -> None:
    """List installed packages on the attached device."""
    _run_runtime("list_adb_packages", "adb", {})


@app.command("android-app-info")
def android_app_info(package: str = typer.Argument(...)) -> None:
    """Dump package facts for one Android package."""
    _run_runtime("android_app_info", "adb", {"package": package})


@app.command("adb-shell")
def adb_shell(
    command: list[str] = typer.Argument(...),
    timeout: float = typer.Option(60.0, "--timeout"),
) -> None:
    """Run a bounded command through 'adb shell'."""
    _run_runtime("adb_shell", "adb", {"command": command, "timeout": timeout})


@app.command("list-frida-devices")
def list_frida_devices() -> None:
    """List Frida devices."""
    _run_runtime("list_frida_devices", "frida", {})


@app.command("list-frida-applications")
def list_frida_applications(device: str | None = typer.Option(None, "--device")) -> None:
    """List applications on a Frida device."""
    _run_runtime("list_frida_applications", "frida", {"device": device})


@app.command("list-frida-processes")
def list_frida_processes(device: str | None = typer.Option(None, "--device")) -> None:
    """List processes on a Frida device."""
    _run_runtime("list_frida_processes", "frida", {"device": device})


@app.command("ida-inspect-provider")
def ida_inspect_provider() -> None:
    """Probe the configured IDA service endpoint."""
    _run_runtime("ida_inspect_provider", "ida", {})


@app.command("jeb-inspect-provider")
def jeb_inspect_provider() -> None:
    """Probe the configured JEB service endpoint."""
    _run_runtime("jeb_inspect_provider", "jeb", {})


@app.command("schema-matrix")
def schema_matrix() -> None:
    """Show the per-client input/output schema posture."""
    from ..config.settings import client_schema_matrix

    emit_json({"clients": client_schema_matrix()})


@app.command("inspect-adb-client")
def inspect_adb_client() -> None:
    """Inspect the caller-selected adb binary and version."""
    _run_runtime("inspect_adb_client", "adb", {})


@app.command("inspect-adb-device")
def inspect_adb_device(
    serial: str = typer.Option(..., "--serial"),
) -> None:
    """Inspect one device's build identity via getprop."""
    _run_runtime("inspect_adb_device", "adb", {"serial": serial})


@app.command("pull-adb-package")
def pull_adb_package(
    serial: str = typer.Option(..., "--serial"),
    package: str = typer.Option(..., "--package"),
    output_directory: str = typer.Option(..., "--output-directory"),
) -> None:
    """Pull every APK of an installed package."""
    _run_runtime(
        "pull_adb_package",
        "adb",
        {"serial": serial, "package": package, "output_directory": output_directory},
    )


@app.command("read-adb-logcat")
def read_adb_logcat(
    serial: str = typer.Option(..., "--serial"),
    count: int = typer.Option(500, "--count"),
    buffer: str = typer.Option("main", "--buffer"),
    pid: int | None = typer.Option(None, "--pid"),
) -> None:
    """Read the most recent logcat lines."""
    _run_runtime(
        "read_adb_logcat", "adb", {"serial": serial, "count": count, "buffer": buffer, "pid": pid}
    )


@app.command("inspect-adb-package")
def inspect_adb_package(
    serial: str = typer.Option(..., "--serial"),
    package: str = typer.Option(..., "--package"),
) -> None:
    """Dump package facts for one installed package."""
    _run_runtime("inspect_adb_package", "adb", {"serial": serial, "package": package})


@app.command("pull-adb-file")
def pull_adb_file(
    serial: str = typer.Option(..., "--serial"),
    device_path: str = typer.Option(..., "--device-path"),
    output_directory: str = typer.Option(..., "--output-directory"),
) -> None:
    """Pull one absolute device file."""
    _run_runtime(
        "pull_adb_file",
        "adb",
        {"serial": serial, "device_path": device_path, "output_directory": output_directory},
    )


@app.command("push-adb-file")
def push_adb_file(
    serial: str = typer.Option(..., "--serial"),
    local_path: str = typer.Option(..., "--local-path"),
    device_path: str = typer.Option(..., "--device-path"),
    overwrite: bool = typer.Option(False, "--overwrite"),
) -> None:
    """Push a local file to an absolute device path."""
    _run_runtime(
        "push_adb_file",
        "adb",
        {
            "serial": serial,
            "local_path": local_path,
            "device_path": device_path,
            "overwrite": overwrite,
        },
    )


@app.command("capture-adb-screen")
def capture_adb_screen(
    serial: str = typer.Option(..., "--serial"),
    output_directory: str = typer.Option(..., "--output-directory"),
) -> None:
    """Capture a PNG screenshot from the device."""
    _run_runtime(
        "capture_adb_screen", "adb", {"serial": serial, "output_directory": output_directory}
    )


@app.command("list-adb-processes")
def list_adb_processes(
    serial: str = typer.Option(..., "--serial"),
) -> None:
    """List device processes (ps -A)."""
    _run_runtime("list_adb_processes", "adb", {"serial": serial})


@app.command("list-adb-directory")
def list_adb_directory(
    serial: str = typer.Option(..., "--serial"),
    device_path: str = typer.Option(..., "--device-path"),
) -> None:
    """List one absolute device directory."""
    _run_runtime("list_adb_directory", "adb", {"serial": serial, "device_path": device_path})


@app.command("list-adb-features")
def list_adb_features(
    serial: str = typer.Option(..., "--serial"),
) -> None:
    """List device package-manager features."""
    _run_runtime("list_adb_features", "adb", {"serial": serial})


@app.command("list-adb-services")
def list_adb_services(
    serial: str = typer.Option(..., "--serial"),
) -> None:
    """List device services."""
    _run_runtime("list_adb_services", "adb", {"serial": serial})


@app.command("inspect-adb-display")
def inspect_adb_display(
    serial: str = typer.Option(..., "--serial"),
) -> None:
    """Dump display state."""
    _run_runtime("inspect_adb_display", "adb", {"serial": serial})


@app.command("inspect-adb-window")
def inspect_adb_window(
    serial: str = typer.Option(..., "--serial"),
) -> None:
    """Dump window state."""
    _run_runtime("inspect_adb_window", "adb", {"serial": serial})


@app.command("read-adb-setting")
def read_adb_setting(
    serial: str = typer.Option(..., "--serial"),
    namespace: str = typer.Option(..., "--namespace"),
    key: str = typer.Option(..., "--key"),
) -> None:
    """Read one settings namespace key."""
    _run_runtime("read_adb_setting", "adb", {"serial": serial, "namespace": namespace, "key": key})


@app.command("collect-adb-bugreport")
def collect_adb_bugreport(
    serial: str = typer.Option(..., "--serial"),
    output_directory: str = typer.Option(..., "--output-directory"),
) -> None:
    """Collect a device bugreport archive."""
    _run_runtime(
        "collect_adb_bugreport", "adb", {"serial": serial, "output_directory": output_directory}
    )


@app.command("resolve-adb-packages")
def resolve_adb_packages(
    serial: str = typer.Option(..., "--serial"),
    query: str = typer.Option(..., "--query"),
) -> None:
    """Resolve packages by case-insensitive substring."""
    _run_runtime("resolve_adb_packages", "adb", {"serial": serial, "query": query})


@app.command("install-adb-package")
def install_adb_package(
    serial: str = typer.Option(..., "--serial"),
    apk_path: str = typer.Option(..., "--apk-path"),
    replace: bool = typer.Option(False, "--replace"),
) -> None:
    """Install a local APK."""
    _run_runtime(
        "install_adb_package", "adb", {"serial": serial, "apk_path": apk_path, "replace": replace}
    )


@app.command("uninstall-adb-package")
def uninstall_adb_package(
    serial: str = typer.Option(..., "--serial"),
    package: str = typer.Option(..., "--package"),
) -> None:
    """Uninstall an installed package."""
    _run_runtime("uninstall_adb_package", "adb", {"serial": serial, "package": package})


@app.command("start-adb-app")
def start_adb_app(
    serial: str = typer.Option(..., "--serial"),
    package: str = typer.Option(..., "--package"),
) -> None:
    """Start an app's launcher activity."""
    _run_runtime("start_adb_app", "adb", {"serial": serial, "package": package})


@app.command("start-adb-activity")
def start_adb_activity(
    serial: str = typer.Option(..., "--serial"),
    action: str = typer.Option(..., "--action"),
    data_uri: str | None = typer.Option(None, "--data-uri"),
    component: str | None = typer.Option(None, "--component"),
    extras_json: str | None = typer.Option(
        None, "--extras-json", help="JSON array of {key,type,value} extra objects."
    ),
) -> None:
    """Start an activity with an intent."""
    extras = json.loads(extras_json) if extras_json else None
    _run_runtime(
        "start_adb_activity",
        "adb",
        {
            "serial": serial,
            "action": action,
            "data_uri": data_uri,
            "component": component,
            "extras": extras,
        },
    )


@app.command("stop-adb-app")
def stop_adb_app(
    serial: str = typer.Option(..., "--serial"),
    package: str = typer.Option(..., "--package"),
) -> None:
    """Force-stop an app."""
    _run_runtime("stop_adb_app", "adb", {"serial": serial, "package": package})


@app.command("inspect-packet-fields")
def inspect_packet_fields(
    path: str = typer.Argument(...),
    limit: int = typer.Option(500, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Per-packet fields for a saved capture."""
    _run("inspect_packet_fields", path, provider, {"limit": limit})


@app.command("inspect-packet-capture")
def inspect_packet_capture(
    path: str = typer.Argument(...), provider: str | None = typer.Option(None, "--provider")
) -> None:
    """Saved capture summary and endpoints."""
    _run("inspect_packet_capture", path, provider, {})


@app.command("inspect-pcap-client")
def inspect_pcap_client() -> None:
    """Inspect the caller-selected tshark client."""
    _run_runtime("inspect_pcap_client", "pcap", {})


@app.command("inspect-signal-decoders")
def inspect_signal_decoders() -> None:
    """List available sigrok signal decoders."""
    _run_runtime("inspect_signal_decoders", "sigrok", {})


@app.command("extract-firmware")
def extract_firmware(
    path: str = typer.Argument(...),
    output: str = typer.Option(..., "--output"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Extract firmware regions to files."""
    _run("extract_firmware", path, provider, {"output_directory": output})


@app.command("inspect-jeb-client")
def inspect_jeb_client() -> None:
    """Inspect the configured JEB service."""
    _run_runtime("inspect_jeb_client", "jeb", {})


@app.command("open-jeb-project")
def open_jeb_project(
    path: str = typer.Argument(...), provider: str | None = typer.Option(None, "--provider")
) -> None:
    """Open a project in JEB."""
    _run("open_jeb_project", path, provider, {})


@app.command("list-jeb-units")
def list_jeb_units(
    path: str = typer.Argument(...), provider: str | None = typer.Option(None, "--provider")
) -> None:
    """List JEB project units."""
    _run("list_jeb_units", path, provider, {})


@app.command("decompile-jeb-item")
def decompile_jeb_item(
    path: str = typer.Argument(...),
    item: str = typer.Option(..., "--item"),
    max_bytes: int = typer.Option(64000, "--max-bytes"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Decompile one JEB unit."""
    _run("decompile_jeb_item", path, provider, {"item": item, "max_bytes": max_bytes})


@app.command("start-frida-session")
def start_frida_session(
    target: str = typer.Option(..., "--target"),
    device: str | None = typer.Option(None, "--device"),
    spawn: bool = typer.Option(False, "--spawn"),
) -> None:
    """Start a Frida session on a process."""
    _run_runtime(
        "start_frida_session", "frida", {"device": device, "target": target, "spawn": spawn}
    )


@app.command("frida-session-status")
def frida_session_status(session_id: str = typer.Option(..., "--session-id")) -> None:
    """Report a Frida session."""
    _run_runtime("frida_session_status", "frida", {"session_id": session_id})


@app.command("load-frida-script")
def load_frida_script(
    session_id: str = typer.Option(..., "--session-id"),
    source: str = typer.Option(..., "--source"),
    name: str | None = typer.Option(None, "--name"),
) -> None:
    """Load a script into a Frida session."""
    _run_runtime(
        "load_frida_script", "frida", {"session_id": session_id, "source": source, "name": name}
    )


@app.command("unload-frida-script")
def unload_frida_script(
    session_id: str = typer.Option(..., "--session-id"),
    name: str = typer.Option(..., "--name"),
) -> None:
    """Unload a Frida script."""
    _run_runtime("unload_frida_script", "frida", {"session_id": session_id, "name": name})


@app.command("resume-frida-session")
def resume_frida_session(session_id: str = typer.Option(..., "--session-id")) -> None:
    """Resume a spawned Frida session."""
    _run_runtime("resume_frida_session", "frida", {"session_id": session_id})


@app.command("close-frida-session")
def close_frida_session(session_id: str = typer.Option(..., "--session-id")) -> None:
    """Close a Frida session."""
    _run_runtime("close_frida_session", "frida", {"session_id": session_id})


@app.command("instrument-with-frida")
def instrument_with_frida(
    target: str = typer.Option(..., "--target"),
    source: str = typer.Option(..., "--source"),
    device: str | None = typer.Option(None, "--device"),
    duration: float = typer.Option(2.0, "--duration"),
) -> None:
    """Attach, run a script briefly, and collect messages."""
    _run_runtime(
        "instrument_with_frida",
        "frida",
        {"device": device, "target": target, "source": source, "duration": duration},
    )


@app.command("current-address")
def current_address(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Current navigation address."""
    _run("current_address", path, provider, {})


@app.command("goto-address")
def goto_address(
    path: str = typer.Argument(...),
    address: str = typer.Option(..., "--address"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Seek to an address."""
    _run("goto_address", path, provider, {"address": address})


@app.command("next-address")
def next_address(
    path: str = typer.Argument(...),
    delta: int = typer.Option(1, "--delta"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Advance the current address."""
    _run("next_address", path, provider, {"delta": delta})


@app.command("prev-address")
def prev_address(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Return to the previous address."""
    _run("prev_address", path, provider, {})


@app.command("current-document")
def current_document(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Current document identity."""
    _run("current_document", path, provider, {})


@app.command("current-procedure")
def current_procedure(
    path: str = typer.Argument(...),
    address: str | None = typer.Option(None, "--address"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Procedure containing the current address."""
    _run("current_procedure", path, provider, {"address": address})


@app.command("list-documents")
def list_documents(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """List open documents."""
    _run("list_documents", path, provider, {})


@app.command("list-segments")
def list_segments(
    path: str = typer.Argument(...),
    limit: int = typer.Option(200, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """List segments."""
    _run("list_segments", path, provider, {"limit": limit})


@app.command("list-strings")
def list_strings(
    path: str = typer.Argument(...),
    limit: int = typer.Option(500, "--limit"),
    raw_image: bool = typer.Option(False, "--raw-image"),
    target: str | None = typer.Option(None, "--target"),
    base: str | None = typer.Option(None, "--base"),
    entry: str | None = typer.Option(None, "--entry"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """List strings."""
    _run(
        "list_strings",
        path,
        provider,
        {"limit": limit, "target": target, "base": base, "entry": entry},
        format_hint="raw-binary" if raw_image else None,
    )


@app.command("list-names")
def list_names(
    path: str = typer.Argument(...),
    limit: int = typer.Option(500, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """List names/flags."""
    _run("list_names", path, provider, {"limit": limit})


@app.command("list-procedures")
def list_procedures(
    path: str = typer.Argument(...),
    limit: int = typer.Option(500, "--limit"),
    raw_image: bool = typer.Option(False, "--raw-image"),
    target: str | None = typer.Option(None, "--target"),
    base: str | None = typer.Option(None, "--base"),
    entry: str | None = typer.Option(None, "--entry"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """List procedures."""
    _run(
        "list_procedures",
        path,
        provider,
        {"limit": limit, "target": target, "base": base, "entry": entry},
        format_hint="raw-binary" if raw_image else None,
    )


@app.command("list-bookmarks")
def list_bookmarks(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """List bookmarks."""
    _run("list_bookmarks", path, provider, {})


@app.command("set-bookmark")
def set_bookmark(
    path: str = typer.Argument(...),
    name: str = typer.Option(..., "--name"),
    address: str | None = typer.Option(None, "--address"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Set a bookmark."""
    _run("set_bookmark", path, provider, {"name": name, "address": address})


@app.command("unset-bookmark")
def unset_bookmark(
    path: str = typer.Argument(...),
    name: str = typer.Option(..., "--name"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Remove a bookmark."""
    _run("unset_bookmark", path, provider, {"name": name})


@app.command("get-navigation-context")
def get_navigation_context(
    path: str = typer.Argument(...),
    address: str | None = typer.Option(None, "--address"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Navigation context at an address."""
    _run("get_navigation_context", path, provider, {"address": address})


@app.command("inspect-address-context")
def inspect_address_context(
    path: str = typer.Argument(...),
    address: str | None = typer.Option(None, "--address"),
    limit: int = typer.Option(200, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Instruction/function/xref context."""
    _run("inspect_address_context", path, provider, {"address": address, "limit": limit})


@app.command("address-name")
def address_name(
    path: str = typer.Argument(...),
    address: str | None = typer.Option(None, "--address"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Name at an address."""
    _run("address_name", path, provider, {"address": address})


@app.command("comment")
def comment(
    path: str = typer.Argument(...),
    address: str | None = typer.Option(None, "--address"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Comment at an address."""
    _run("comment", path, provider, {"address": address})


@app.command("inline-comment")
def inline_comment(
    path: str = typer.Argument(...),
    address: str | None = typer.Option(None, "--address"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Inline comment at an address."""
    _run("inline_comment", path, provider, {"address": address})


@app.command("set-address-name")
def set_address_name(
    path: str = typer.Argument(...),
    address: str | None = typer.Option(None, "--address"),
    name: str = typer.Option(..., "--name"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Rename a function at an address."""
    _run("set_address_name", path, provider, {"address": address, "name": name})


@app.command("set-addresses-names")
def set_addresses_names(
    path: str = typer.Argument(...),
    assignments_json: str = typer.Option(..., "--assignments-json"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Apply multiple address renames."""
    _run("set_addresses_names", path, provider, {"assignments": json.loads(assignments_json)})


@app.command("set-comment")
def set_comment(
    path: str = typer.Argument(...),
    address: str | None = typer.Option(None, "--address"),
    comment: str = typer.Option(..., "--comment"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Set a comment at an address."""
    _run("set_comment", path, provider, {"address": address, "comment": comment})


@app.command("set-inline-comment")
def set_inline_comment(
    path: str = typer.Argument(...),
    address: str | None = typer.Option(None, "--address"),
    comment: str = typer.Option(..., "--comment"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Set an inline comment at an address."""
    _run("set_inline_comment", path, provider, {"address": address, "comment": comment})


@app.command("annotate-native-function")
def annotate_native_function(
    path: str = typer.Argument(...),
    address: str | None = typer.Option(None, "--address"),
    name: str | None = typer.Option(None, "--name"),
    comment: str | None = typer.Option(None, "--comment"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Rename and/or comment one function."""
    _run(
        "annotate_native_function",
        path,
        provider,
        {"address": address, "name": name, "comment": comment},
    )


@app.command("procedure-address")
def procedure_address(
    path: str = typer.Argument(...),
    function: str = typer.Option("main", "--function"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Entry address of a procedure."""
    _run("procedure_address", path, provider, {"function": function})


@app.command("procedure-assembly")
def procedure_assembly(
    path: str = typer.Argument(...),
    function: str = typer.Option("main", "--function"),
    limit: int = typer.Option(500, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Disassembly of a procedure."""
    _run("procedure_assembly", path, provider, {"function": function, "limit": limit})


@app.command("procedure-callees")
def procedure_callees(
    path: str = typer.Argument(...),
    function: str = typer.Option("main", "--function"),
    limit: int = typer.Option(200, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Callees of a procedure."""
    _run("procedure_callees", path, provider, {"function": function, "limit": limit})


@app.command("procedure-callers")
def procedure_callers(
    path: str = typer.Argument(...),
    function: str = typer.Option("main", "--function"),
    limit: int = typer.Option(200, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Callers of a procedure."""
    _run("procedure_callers", path, provider, {"function": function, "limit": limit})


@app.command("procedure-info")
def procedure_info(
    path: str = typer.Argument(...),
    function: str = typer.Option("main", "--function"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Procedure metadata."""
    _run("procedure_info", path, provider, {"function": function})


@app.command("procedure-pseudo-code")
def procedure_pseudo_code(
    path: str = typer.Argument(...),
    function: str = typer.Option("main", "--function"),
    max_bytes: int = typer.Option(64000, "--max-bytes"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Pseudocode for a procedure."""
    _run(
        "procedure_pseudo_code",
        path,
        provider,
        {"function": function, "max_bytes": max_bytes},
    )


@app.command("procedure-references")
def procedure_references(
    path: str = typer.Argument(...),
    function: str = typer.Option("main", "--function"),
    limit: int = typer.Option(200, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Callers and callees."""
    _run("procedure_references", path, provider, {"function": function, "limit": limit})


@app.command("resolve-containing-procedure")
def resolve_containing_procedure(
    path: str = typer.Argument(...),
    address: str | None = typer.Option(None, "--address"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Resolve the procedure containing an address."""
    _run("resolve_containing_procedure", path, provider, {"address": address})


@app.command("resolve-native-call-targets")
def resolve_native_call_targets(
    path: str = typer.Argument(...),
    address: str | None = typer.Option(None, "--address"),
    limit: int = typer.Option(200, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Resolve call targets at an address."""
    _run("resolve_native_call_targets", path, provider, {"address": address, "limit": limit})


@app.command("read-function-instructions")
def read_function_instructions(
    path: str = typer.Argument(...),
    address: str | None = typer.Option(None, "--address"),
    count: int = typer.Option(64, "--count"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Instructions for a function/address."""
    _run("read_function_instructions", path, provider, {"address": address, "count": count})


@app.command("search-procedures")
def search_procedures(
    path: str = typer.Argument(...),
    query: str = typer.Option(..., "--query"),
    limit: int = typer.Option(200, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Search procedure names."""
    _run("search_procedures", path, provider, {"query": query, "limit": limit})


@app.command("search-strings")
def search_strings(
    path: str = typer.Argument(...),
    query: str = typer.Option(..., "--query"),
    limit: int = typer.Option(200, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Search strings."""
    _run("search_strings", path, provider, {"query": query, "limit": limit})


@app.command("find-xrefs-to-name")
def find_xrefs_to_name(
    path: str = typer.Argument(...),
    name: str = typer.Option(..., "--name"),
    limit: int = typer.Option(200, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Cross-references to a named symbol."""
    _run("find_xrefs_to_name", path, provider, {"name": name, "limit": limit})


@app.command("inspect-native-data-type")
def inspect_native_data_type(
    path: str = typer.Argument(...),
    limit: int = typer.Option(200, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Recovered types."""
    _run("inspect_native_data_type", path, provider, {"limit": limit})


@app.command("inspect-native-instruction")
def inspect_native_instruction(
    path: str = typer.Argument(...),
    address: str | None = typer.Option(None, "--address"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Decoded instruction at an address."""
    _run("inspect_native_instruction", path, provider, {"address": address})


@app.command("inspect-native-load-image")
def inspect_native_load_image(
    path: str = typer.Argument(...),
    limit: int = typer.Option(200, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Loaded image verification facts."""
    _run("inspect_native_load_image", path, provider, {"limit": limit})


@app.command("inspect-native-api")
def inspect_native_api(
    path: str = typer.Argument(...),
    limit: int = typer.Option(500, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Imported API inventory."""
    _run("inspect_native_api", path, provider, {"limit": limit})


@app.command("analyze-swift-types")
def analyze_swift_types(
    path: str = typer.Argument(...),
    limit: int = typer.Option(200, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Objective-C/Swift metadata."""
    _run("analyze_swift_types", path, provider, {"limit": limit})


@app.command("get-objc-classes")
def get_objc_classes(
    path: str = typer.Argument(...),
    limit: int = typer.Option(200, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Objective-C classes."""
    _run("get_objc_classes", path, provider, {"limit": limit})


@app.command("get-objc-protocols")
def get_objc_protocols(
    path: str = typer.Argument(...),
    limit: int = typer.Option(200, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Objective-C protocols."""
    _run("get_objc_protocols", path, provider, {"limit": limit})


@app.command("start-gdb-session")
def start_gdb_session(
    path: str = typer.Argument(...),
    args: list[str] | None = typer.Option(None, "--args"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Start a GDB session."""
    _run("start_gdb_session", path, provider, {"args": args})


@app.command("gdb-session-status")
def gdb_session_status(
    session_id: str = typer.Option(..., "--session-id"),
) -> None:
    """Report a GDB session."""
    _run_runtime("gdb_session_status", "debug", {"session_id": session_id})


@app.command("close-gdb-session")
def close_gdb_session(
    session_id: str = typer.Option(..., "--session-id"),
) -> None:
    """Close a GDB session."""
    _run_runtime("close_gdb_session", "debug", {"session_id": session_id})


@app.command("gdb-console")
def gdb_console(
    path: str = typer.Argument(...),
    commands: list[str] = typer.Option(..., "--commands"),
    timeout: float = typer.Option(120.0, "--timeout"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Run GDB batch commands."""
    _run("gdb_console", path, provider, {"commands": commands, "timeout": timeout})


@app.command("start-rizin-debug-session")
def start_rizin_debug_session(
    path: str = typer.Argument(...),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Start a Rizin debug session."""
    _run("start_rizin_debug_session", path, provider, {})


@app.command("rizin-debug-session-status")
def rizin_debug_session_status(
    session_id: str = typer.Option(..., "--session-id"),
) -> None:
    """Report a Rizin debug session."""
    _run_runtime("rizin_debug_session_status", "debug", {"session_id": session_id})


@app.command("close-rizin-debug-session")
def close_rizin_debug_session(
    session_id: str = typer.Option(..., "--session-id"),
) -> None:
    """Close a Rizin debug session."""
    _run_runtime("close_rizin_debug_session", "debug", {"session_id": session_id})


@app.command("rizin-debug-command")
def rizin_debug_command(
    path: str = typer.Argument(...),
    command: str = typer.Option(..., "--command"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Run a Rizin debug command."""
    _run("rizin_debug_command", path, provider, {"command": command})


@app.command("execute-rizin-command")
def execute_rizin_command(
    path: str = typer.Argument(...),
    command: str = typer.Option(..., "--command"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Run a Rizin command."""
    _run("execute_rizin_command", path, provider, {"command": command})


@app.command("list-cutter-sessions")
def list_cutter_sessions() -> None:
    """List Cutter bridge sessions."""
    _run_runtime("list_cutter_sessions", "debug", {})


@app.command("cutter-command")
def cutter_command(
    path: str = typer.Argument(...),
    command: str = typer.Option(..., "--command"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Run a command through the Cutter bridge."""
    _run("cutter_command", path, provider, {"command": command})


@app.command("get-evidence-bundle")
def get_evidence_bundle(full: bool = typer.Option(False, "--full")) -> None:
    """Return the session Evidence bundle (summary by default)."""
    from ..application.workflows import get_evidence_bundle as _bundle

    session, config = _session()
    emit_json(_bundle(session, full=full, budget_bytes=config.mcp_max_response_bytes))


@app.command("verify-reconstruction")
def verify_reconstruction(
    ledger_json: str = typer.Option(..., "--ledger-json"),
) -> None:
    """Verify a reconstruction ledger."""
    from ..application.workflows import verify_reconstruction as _verify

    emit_json(_verify(json.loads(ledger_json)))


@app.command("verify-unknown-resolution")
def verify_unknown_resolution(
    unknown_id: str = typer.Option(..., "--unknown-id"),
) -> None:
    """Verify an unknown's resolution status."""
    from ..application.workflows import verify_unknown_resolution as _verify

    session, _config = _session()
    emit_json(_verify(session, unknown_id))


@app.command("compare-bundles")
def compare_bundles(
    left: str = typer.Option(..., "--left"), right: str = typer.Option(..., "--right")
) -> None:
    """Compare two Evidence bundles."""
    from ..application.workflows import compare_bundles as _compare

    emit_json(_compare(left, right))


@app.command("compare-functions")
def compare_functions(
    left: str = typer.Option(..., "--left"), right: str = typer.Option(..., "--right")
) -> None:
    """Compare function inventories from two Evidence files."""
    from ..application.workflows import compare_functions as _compare

    emit_json(_compare(left, right))


@app.command("compare-process-captures")
def compare_process_captures(
    left: str = typer.Option(..., "--left"), right: str = typer.Option(..., "--right")
) -> None:
    """Compare two process captures."""
    from ..application.workflows import compare_process_captures as _compare

    emit_json(_compare(left, right))


@app.command("correlate-static-and-runtime")
def correlate_static_and_runtime(
    left: str = typer.Option(..., "--left"), right: str = typer.Option(..., "--right")
) -> None:
    """Correlate static and runtime Evidence operations."""
    from ..application.workflows import correlate_static_and_runtime as _correlate

    emit_json(_correlate(left, right))


@app.command("find-changed-behavior")
def find_changed_behavior(
    left: str = typer.Option(..., "--left"), right: str = typer.Option(..., "--right")
) -> None:
    """Find changed Evidence between two bundles."""
    from ..application.workflows import find_changed_behavior as _find

    emit_json(_find(left, right))


@app.command("batch-decompile")
def batch_decompile(
    path: str = typer.Argument(...),
    functions: list[str] = typer.Option(..., "--function"),
    max_bytes_per_function: int = typer.Option(64000, "--max-bytes-per-function"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Decompile multiple functions."""
    from ..application.workflows import batch_decompile as _batch

    _run_session(
        path,
        provider,
        lambda session: _batch(session, functions, max_bytes_per_function=max_bytes_per_function),
    )


@app.command("get-call-graph")
def get_call_graph(
    path: str = typer.Argument(...),
    limit: int = typer.Option(50, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Build a function call graph."""
    from ..application.workflows import get_call_graph as _graph

    _run_session(path, provider, lambda session: _graph(session, limit=limit))


@app.command("build-call-path")
def build_call_path(
    path: str = typer.Argument(...),
    from_function: str = typer.Option(..., "--from"),
    to_function: str = typer.Option(..., "--to"),
    limit: int = typer.Option(50, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Find a call path between two functions."""
    from ..application.workflows import build_call_path as _path

    _run_session(
        path, provider, lambda session: _path(session, from_function, to_function, limit=limit)
    )


@app.command("trace-call-path")
def trace_call_path(
    path: str = typer.Argument(...),
    from_function: str = typer.Option(..., "--from"),
    to_function: str = typer.Option(..., "--to"),
    limit: int = typer.Option(50, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Trace a call path between two functions."""
    from ..application.workflows import trace_call_path as _path

    _run_session(
        path, provider, lambda session: _path(session, from_function, to_function, limit=limit)
    )


@app.command("trace-feature")
def trace_feature(
    path: str = typer.Argument(...),
    feature: str = typer.Option(..., "--feature"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Trace a feature across strings, procedures and xrefs."""
    from ..application.workflows import trace_feature as _trace

    _run_session(path, provider, lambda session: _trace(session, feature))


@app.command("trace-native-values")
def trace_native_values(
    path: str = typer.Argument(...),
    query: str = typer.Option(..., "--query"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Trace values across strings and matches."""
    from ..application.workflows import trace_native_values as _trace

    _run_session(path, provider, lambda session: _trace(session, query))


@app.command("inspect-apktool-client")
def inspect_apktool_client() -> None:
    """Inspect the caller-selected apktool binary."""
    _run_runtime("inspect_apktool_client", "apktool", {})


@app.command("inspect-dart-aot")
def inspect_dart_aot(
    path: str = typer.Argument(...), provider: str | None = typer.Option(None, "--provider")
) -> None:
    """Static Dart AOT snapshot facts."""
    _run("inspect_dart_aot", path, provider, {})


@app.command("search-android-classes")
def search_android_classes(
    path: str = typer.Argument(...),
    query: str = typer.Option(..., "--query"),
    limit: int = typer.Option(200, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Search decompiled Android classes."""
    _run("search_android_classes", path, provider, {"query": query, "limit": limit})


@app.command("inspect-android-class")
def inspect_android_class(
    path: str = typer.Argument(...),
    class_name: str = typer.Option(..., "--class"),
    offset: int = typer.Option(0, "--offset"),
    limit: int = typer.Option(500, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Inspect one decompiled Android class."""
    _run(
        "inspect_android_class",
        path,
        provider,
        {"class_name": class_name, "offset": offset, "limit": limit},
    )


@app.command("inspect-android-method")
def inspect_android_method(
    path: str = typer.Argument(...),
    class_name: str = typer.Option(..., "--class"),
    method: str = typer.Option(..., "--method"),
    offset: int = typer.Option(0, "--offset"),
    limit: int = typer.Option(500, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Inspect one Android method."""
    _run(
        "inspect_android_method",
        path,
        provider,
        {
            "class_name": class_name,
            "method": method,
            "offset": offset,
            "limit": limit,
        },
    )


@app.command("trace-android-references")
def trace_android_references(
    path: str = typer.Argument(...),
    query: str = typer.Option(..., "--query"),
    limit: int = typer.Option(200, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Search references across decompiled sources."""
    _run("trace_android_references", path, provider, {"query": query, "limit": limit})


@app.command("list-browser-targets")
def list_browser_targets(
    endpoint: str | None = typer.Option(None, "--endpoint"),
) -> None:
    """List browser CDP targets."""
    _run_runtime("list_browser_targets", "cdp", {"endpoint": endpoint})


@app.command("list-electron-targets")
def list_electron_targets(
    endpoint: str | None = typer.Option(None, "--endpoint"),
) -> None:
    """List Electron CDP targets."""
    _run_runtime("list_electron_targets", "cdp", {"endpoint": endpoint})


@app.command("list-javascript-runtime-targets")
def list_javascript_runtime_targets(
    endpoint: str | None = typer.Option(None, "--endpoint"),
) -> None:
    """List JavaScript runtime targets."""
    _run_runtime("list_javascript_runtime_targets", "cdp", {"endpoint": endpoint})


@app.command("inspect-web-page")
def inspect_web_page(
    url: str = typer.Option(..., "--url"),
) -> None:
    """Inspect a page's title, scripts, forms and meta."""
    _run_runtime("inspect_web_page", url, {"url": url})


@app.command("inspect-web-event-listeners")
def inspect_web_event_listeners(
    url: str = typer.Option(..., "--url"),
    selector: str | None = typer.Option(None, "--selector"),
) -> None:
    """Inspect inline handlers and native listener source locations."""
    _run_runtime("inspect_web_event_listeners", url, {"url": url, "selector": selector})


@app.command("observe-web-execution")
def observe_web_execution(
    url: str = typer.Option(..., "--url"),
    duration: float = typer.Option(3.0, "--duration"),
    bodies: bool = typer.Option(False, "--bodies"),
    retain_bodies: bool = typer.Option(False, "--retain-bodies"),
) -> None:
    """Observe console output and requests; optionally capture XHR/fetch bodies."""
    _run_runtime(
        "observe_web_execution",
        url,
        {
            "url": url,
            "duration": duration,
            "capture_bodies": bodies,
            "retain_bodies": retain_bodies,
        },
    )


@app.command("observe-web-session")
def observe_web_session(
    url: str = typer.Option(..., "--url"),
) -> None:
    """Observe cookies and web storage."""
    _run_runtime("observe_web_session", url, {"url": url})


@app.command("capture-web-screenshot")
def capture_web_screenshot(
    url: str = typer.Option(..., "--url"),
    output: str = typer.Option(..., "--output"),
    full_page: bool = typer.Option(False, "--full-page"),
) -> None:
    """Capture a page screenshot."""
    _run_runtime(
        "capture_web_screenshot",
        "url",
        {"url": url, "output": output, "full_page": full_page},
    )


@app.command("compare-web-screenshots")
def compare_web_screenshots(
    left: str = typer.Option(..., "--left"),
    right: str = typer.Option(..., "--right"),
) -> None:
    """Compare two screenshots."""
    _run_runtime("compare_web_screenshots", "web", {"left": left, "right": right})


@app.command("capture-browser-scenario")
def capture_browser_scenario(
    steps_json: str | None = typer.Option(None, "--steps-json"),
) -> None:
    """Run a browser scenario."""
    _run_runtime(
        "capture_browser_scenario", "web", {"steps": json.loads(steps_json) if steps_json else None}
    )


@app.command("capture-electron-scenario")
def capture_electron_scenario(
    endpoint: str | None = typer.Option(None, "--endpoint"),
    steps_json: str | None = typer.Option(None, "--steps-json"),
    app: str | None = typer.Option(None, "--app"),
    executable: str | None = typer.Option(None, "--executable"),
    port: int = typer.Option(0, "--port"),
    launch_arg: list[str] = typer.Option([], "--launch-arg"),
    launch_timeout: float = typer.Option(20.0, "--launch-timeout"),
) -> None:
    """Run an Electron/CDP scenario."""
    _run_runtime(
        "capture_electron_scenario",
        "cdp",
        {
            "endpoint": endpoint,
            "steps": json.loads(steps_json) if steps_json else None,
            "app": app,
            "executable": executable,
            "port": port,
            "launch_args": launch_arg,
            "launch_timeout": launch_timeout,
        },
    )


@app.command("inspect-electron-page")
def inspect_electron_page(
    endpoint: str | None = typer.Option(None, "--endpoint"),
) -> None:
    """Inspect an Electron page target."""
    _run_runtime("inspect_electron_page", "cdp", {"endpoint": endpoint})


@app.command("observe-javascript-runtime")
def observe_javascript_runtime(
    endpoint: str | None = typer.Option(None, "--endpoint"),
) -> None:
    """List runtime targets."""
    _run_runtime("observe_javascript_runtime", "cdp", {"endpoint": endpoint})


@app.command("reconcile-javascript-runtime")
def reconcile_javascript_runtime(
    endpoint: str | None = typer.Option(None, "--endpoint"),
    left: str | None = typer.Option(None, "--left"),
    right: str | None = typer.Option(None, "--right"),
) -> None:
    """Reconcile runtime target sets."""
    _run_runtime(
        "reconcile_javascript_runtime",
        "cdp",
        {"endpoint": endpoint, "left": left, "right": right},
    )


@app.command("analyze-web-bundle")
def analyze_web_bundle(
    path: str = typer.Argument(...),
) -> None:
    """Analyze a local JavaScript bundle."""
    _run_runtime("analyze_web_bundle", path, {"path": path})


@app.command("export-web-scripts")
def export_web_scripts(
    url: str = typer.Option(..., "--url"),
    output: str = typer.Option(..., "--output"),
) -> None:
    """Export page scripts to files."""
    _run_runtime("export_web_scripts", url, {"url": url, "output": output})


@app.command("recover-javascript-sources")
def recover_javascript_sources(
    url: str = typer.Option(..., "--url"),
    output: str = typer.Option(..., "--output"),
) -> None:
    """Recover sources from source maps."""
    _run_runtime("recover_javascript_sources", url, {"url": url, "output": output})


@app.command("trace-web-module-imports")
def trace_web_module_imports(
    url: str = typer.Option(..., "--url"),
) -> None:
    """Trace module imports across scripts."""
    _run_runtime("trace_web_module_imports", url, {"url": url})


@app.command("trace-web-source-location")
def trace_web_source_location(
    source_url: str = typer.Option(..., "--source-url"),
    symbol: str = typer.Option(..., "--symbol"),
) -> None:
    """Find a symbol in a source file."""
    _run_runtime(
        "trace_web_source_location", source_url, {"source_url": source_url, "symbol": symbol}
    )


@app.command("invoke-webmcp-tool")
def invoke_webmcp_tool(
    url: str = typer.Option(..., "--url"),
    name: str = typer.Option(..., "--name"),
    arguments: str = typer.Option("{}", "--arguments", help="JSON object passed to the handler."),
) -> None:
    """Explicitly invoke a registered WebMCP tool."""
    try:
        parsed = json.loads(arguments)
    except json.JSONDecodeError as cause:
        fail(AnalysisInputError(operation="invoke_webmcp_tool", message=str(cause)))
    if not isinstance(parsed, dict):
        fail(
            AnalysisInputError(
                operation="invoke_webmcp_tool", message="arguments must be a JSON object"
            )
        )
    _run_runtime(
        "invoke_webmcp_tool",
        url,
        {"url": url, "name": name, "arguments": parsed},
    )


@app.command("discover-webmcp-tools")
def discover_webmcp_tools(
    url: str = typer.Option(..., "--url"),
) -> None:
    """Discover WebMCP declarations."""
    _run_runtime("discover_webmcp_tools", url, {"url": url})


@app.command("trace-native-ui-action")
def trace_native_ui_action(
    selector: str | None = typer.Option(None, "--selector"),
    value: str | None = typer.Option(None, "--value"),
) -> None:
    """Trace a native UI action."""
    _run_runtime("trace_native_ui_action", "web", {"selector": selector, "value": value})


@app.command("binary-overview")
def binary_overview(
    path: str = typer.Argument(...), provider: str | None = typer.Option(None, "--provider")
) -> None:
    """Alias for the provider overview analysis."""
    _run("analyze", path, provider, {})


@app.command("analyze-function")
def analyze_function(
    path: str = typer.Argument(...),
    function: str = typer.Option("main", "--function"),
    limit: int = typer.Option(200, "--limit"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Alias for function inventory/selection."""
    _run("function", path, provider, {"function": function, "limit": limit})


@app.command("capture-process-scenario")
def capture_process_scenario(
    command: list[str] = typer.Argument(...),
    timeout: float = typer.Option(30.0, "--timeout"),
    cwd: str | None = typer.Option(None, "--cwd"),
) -> None:
    """Alias for bounded process capture."""
    captured = capture_process_op(command, timeout=timeout, cwd=cwd)
    if not captured.ok:
        fail(captured.error)
    emit_json(captured.value)


@app.command("compare-artifacts")
def compare_artifacts(
    left: str = typer.Option(..., "--left"), right: str = typer.Option(..., "--right")
) -> None:
    """Alias for comparing saved Evidence records."""
    emit_json(compare_evidence_fn(_load_record(left), _load_record(right)).model_dump())


@app.command("export-evidence-bundle")
def export_evidence_bundle(path: str = typer.Option(..., "--path")) -> None:
    """Alias for Evidence bundle export."""
    session, _config = _session()
    bundle = session.export_bundle()
    Path(path).write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    emit_json({"path": path, "record_count": len(bundle.get("records", []))})


@app.command("import-evidence-bundle")
def import_evidence_bundle(path: str = typer.Option(..., "--path")) -> None:
    """Alias for Evidence bundle import."""
    session, _config = _session()
    imported = session.import_bundle(json.loads(Path(path).read_text(encoding="utf-8")))
    if not imported.ok:
        fail(imported.error)
    emit_json({"imported": True, "delta": imported.value.__dict__})


@app.command("inspect-web-network-capture")
def inspect_web_network_capture(
    path: str = typer.Argument(...), provider: str | None = typer.Option(None, "--provider")
) -> None:
    """Alias for HAR/SAZ capture inspection."""
    _run("inspect_network_capture", path, provider, {})


@app.command("inspect")
def inspect_alias(
    path: str = typer.Argument(...), provider: str | None = typer.Option(None, "--provider")
) -> None:
    """Alias for provider overview analysis."""
    _run("analyze", path, provider, {})


@app.command("trace")
def trace_alias(
    path: str = typer.Argument(...),
    feature: str = typer.Option(..., "--feature"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Trace a feature across strings, procedures and xrefs."""
    from ..application.workflows import trace_feature as _trace

    _run_session(path, provider, lambda session: _trace(session, feature))


@app.command("debug-with-gdb")
def debug_with_gdb(
    path: str = typer.Argument(...),
    commands: list[str] = typer.Option(..., "--command"),
    timeout: float = typer.Option(120.0, "--timeout"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Run GDB batch commands."""
    _run("gdb_console", path, provider, {"commands": commands, "timeout": timeout})


@app.command("debug-with-rizin")
def debug_with_rizin(
    path: str = typer.Argument(...),
    command: str = typer.Option(..., "--command"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Run a Rizin debug command."""
    _run("rizin_debug_command", path, provider, {"command": command})


@app.command("list-objdump-architectures")
def list_objdump_architectures() -> None:
    """List objdump's supported architectures."""
    from ..application import cli_compat

    _compat(cli_compat.list_objdump_architectures)


@app.command("decode-interface-builder")
def decode_interface_builder(
    path: str = typer.Argument(...), provider: str | None = typer.Option(None, "--provider")
) -> None:
    """Decode a compiled Interface Builder archive."""
    _run("inspect_interface_builder", path, provider, {})


@app.command("trace-application-feature")
def trace_application_feature(
    path: str = typer.Argument(...),
    feature: str = typer.Option(..., "--feature"),
    provider: str | None = typer.Option(None, "--provider"),
) -> None:
    """Trace a feature across strings, procedures and xrefs."""
    from ..application.workflows import trace_feature as _trace

    _run_session(path, provider, lambda session: _trace(session, feature))


@app.command("inspect-evidence-bundle")
def inspect_evidence_bundle(
    source: str = typer.Argument(...),
    view: str = typer.Option("summary", "--view"),
    offset: int = typer.Option(0, "--offset"),
    limit: int = typer.Option(64, "--limit"),
    paths: list[str] = typer.Option([], "--path"),
    property_keys: list[str] = typer.Option([], "--property-key"),
    evidence_id: str | None = typer.Option(None, "--evidence-id"),
    collection: str | None = typer.Option(None, "--collection"),
) -> None:
    """Project a saved Evidence bundle."""
    projected = load_view(
        source,
        view,
        offset=offset,
        limit=limit,
        paths=list(paths) or None,
        property_keys=list(property_keys) or None,
        evidence_id=evidence_id,
        collection=collection,
        budget_bytes=AppConfig().mcp_max_response_bytes,
    )
    if not projected.ok:
        fail(projected.error)
    emit_json(projected.value)


@app.command("uninstall")
def uninstall(
    config: str | None = typer.Option(None, "--config"),
    skill_dir: str | None = typer.Option(None, "--skill-dir"),
) -> None:
    """Remove the rea-mcp server entry and/or installed skill."""
    from ..application import cli_compat

    _compat(lambda: cli_compat.uninstall(config, skill_dir))


@app.command("address-to-file-offset")
def address_to_file_offset(
    path: str = typer.Argument(...), address: str = typer.Option(..., "--address")
) -> None:
    """Map a virtual address to a file offset."""
    from ..application import cli_compat

    _compat(lambda: cli_compat.address_to_file_offset(path, address))


@app.command("read-bytes")
def read_bytes(
    path: str = typer.Argument(...),
    offset: int | None = typer.Option(None, "--offset"),
    length: int = typer.Option(64, "--length"),
    address: str | None = typer.Option(None, "--address"),
) -> None:
    """Read bytes at a file offset or mapped virtual address."""
    from ..application import cli_compat

    _compat(lambda: cli_compat.read_bytes(path, offset, length, address=address))


@app.command("search-bytes")
def search_bytes(
    path: str = typer.Argument(...),
    pattern: str = typer.Option(..., "--pattern"),
    hex_pattern: bool = typer.Option(False, "--hex"),
    limit: int = typer.Option(100, "--limit"),
    address: str | None = typer.Option(None, "--address"),
) -> None:
    """Search a byte pattern (optionally starting at a virtual address)."""
    from ..application import cli_compat

    _compat(
        lambda: cli_compat.search_bytes(
            path, pattern, hex_pattern=hex_pattern, limit=limit, address=address
        )
    )


@app.command("list-architectures")
def list_architectures() -> None:
    """List architectures supported by the built-in parsers."""
    from ..application import cli_compat

    _compat(cli_compat.list_architectures)


@app.command("inspect-macho")
def inspect_macho(path: str = typer.Argument(...)) -> None:
    """Inspect a Mach-O image."""
    from ..application import cli_compat

    _compat(lambda: cli_compat.inspect_macho(path))


@app.command("inspect-signature")
def inspect_signature(path: str = typer.Argument(...)) -> None:
    """Inspect a Mach-O code signature."""
    from ..application import cli_compat

    _compat(lambda: cli_compat.inspect_signature(path))


@app.command("demangle-swift")
def demangle_swift(symbols: list[str] = typer.Argument(...)) -> None:
    """Demangle Swift symbols."""
    from ..application import cli_compat

    _compat(lambda: cli_compat.demangle_swift(symbols))


@app.command("extract-artifact")
def extract_artifact(
    path: str = typer.Argument(...),
    output: str = typer.Option(..., "--output"),
    overwrite: bool = typer.Option(False, "--overwrite"),
) -> None:
    """Extract a zip or tar artifact."""
    from ..application import cli_compat

    _compat(lambda: cli_compat.extract_artifact(path, output, overwrite=overwrite))


@app.command("match-native-functions")
def match_native_functions(
    left: str = typer.Argument(...),
    right: str = typer.Argument(...),
    query: str | None = typer.Option(None, "--query"),
    limit: int = typer.Option(100, "--limit"),
) -> None:
    """Match exact native export names between two binaries."""
    from ..application.native_matching import match_native_functions as _match

    try:
        emit_json(_match(left, right, query, limit))
    except Exception as cause:
        fail(AnalysisInputError(operation="match_native_functions", message=str(cause)))


@app.command("compare-wasm-interfaces")
def compare_wasm_interfaces(
    left: str = typer.Option(..., "--left"), right: str = typer.Option(..., "--right")
) -> None:
    """Compare WASM exports and imports."""
    from ..application import cli_compat

    _compat(lambda: cli_compat.compare_wasm_interfaces(left, right))


@app.command("compare-source-to-bundle")
def compare_source_to_bundle(
    source: str = typer.Option(..., "--source"), bundle: str = typer.Option(..., "--bundle")
) -> None:
    """Compare source files to a JS bundle."""
    from ..application import cli_compat

    _compat(lambda: cli_compat.compare_source_to_bundle(source, bundle))


@app.command("compare-javascript-export-shapes")
def compare_javascript_export_shapes(
    left: str = typer.Option(..., "--left"), right: str = typer.Option(..., "--right")
) -> None:
    """Compare JavaScript export shapes."""
    from ..application import cli_compat

    _compat(lambda: cli_compat.compare_javascript_export_shapes(left, right))


@app.command("compare-application-versions")
def compare_application_versions(
    left: str = typer.Option(..., "--left"), right: str = typer.Option(..., "--right")
) -> None:
    """Compare two application versions."""
    from ..application import cli_compat

    _compat(lambda: cli_compat.compare_application_versions(left, right))


@app.command("trace-javascript-semantics")
def trace_javascript_semantics(path: str = typer.Argument(...)) -> None:
    """Trace JavaScript module semantics."""
    from ..application import cli_compat

    _compat(lambda: cli_compat.trace_javascript_semantics(path))


@app.command("project-android-application-graph")
def project_android_application_graph(path: str = typer.Argument(...)) -> None:
    """Project an Android application graph."""
    from ..application import cli_compat

    _compat(lambda: cli_compat.project_android_application_graph(path))


@app.command("project-apple-application-graph")
def project_apple_application_graph(path: str = typer.Argument(...)) -> None:
    """Project an Apple application graph."""
    from ..application import cli_compat

    _compat(lambda: cli_compat.project_apple_application_graph(path))


@app.command("project-harmony-application-graph")
def project_harmony_application_graph(path: str = typer.Argument(...)) -> None:
    """Project a Harmony application graph."""
    from ..application import cli_compat

    _compat(lambda: cli_compat.project_harmony_application_graph(path))


@app.command("project-managed-application-graph")
def project_managed_application_graph(path: str = typer.Argument(...)) -> None:
    """Project a managed application graph."""
    from ..application import cli_compat

    _compat(lambda: cli_compat.project_managed_application_graph(path))


@app.command("import-managed-reconstruction")
def import_managed_reconstruction(path: str = typer.Argument(...)) -> None:
    """Import a managed reconstruction ledger."""
    from ..application import cli_compat

    _compat(lambda: cli_compat.import_managed_reconstruction(path))


@app.command("inspect-managed-native-boundaries")
def inspect_managed_native_boundaries(path: str = typer.Argument(...)) -> None:
    """Inspect managed/native boundaries."""
    from ..application import cli_compat

    _compat(lambda: cli_compat.inspect_managed_native_boundaries(path))


@app.command("verify-managed-native-boundaries")
def verify_managed_native_boundaries(
    path: str = typer.Argument(...),
    boundaries: list[str] = typer.Option(..., "--boundary"),
) -> None:
    """Verify declared managed/native boundaries."""
    from ..application import cli_compat

    _compat(lambda: cli_compat.verify_managed_native_boundaries(path, boundaries))


@app.command("inspect-native-dispatch-metadata")
def inspect_native_dispatch_metadata(path: str = typer.Argument(...)) -> None:
    """Inspect native dispatch metadata."""
    from ..application import cli_compat

    _compat(lambda: cli_compat.inspect_native_dispatch_metadata(path))


@app.command("observe-native-calls")
def observe_native_calls(
    target: str = typer.Argument(..., help="PID or process name; with --spawn, an executable."),
    args: list[str] = typer.Option([], "--arg"),
    duration: float = typer.Option(3.0, "--duration"),
    spawn: bool = typer.Option(False, "--spawn"),
    timeout: float = typer.Option(20.0, "--timeout"),
    allow_execute: bool = typer.Option(False, "--allow-execute"),
) -> None:
    """Observe native calls via Frida (attach by default; --spawn to execute)."""
    from ..application import cli_compat

    _compat(
        lambda: cli_compat.observe_native_calls(
            target,
            args=list(args),
            duration=duration,
            spawn=spawn,
            allow_execute=allow_execute,
            timeout=timeout,
        )
    )


@app.command("observe-native-ui")
def observe_native_ui(
    process: str = typer.Option(..., "--process"),
    allow_ui: bool = typer.Option(False, "--allow-ui"),
) -> None:
    """Observe a macOS process's UI elements via System Events."""
    from ..application import cli_compat

    _compat(lambda: cli_compat.observe_native_ui(process, allow_ui=allow_ui))


@app.command("capture-native-ui-scenario")
def capture_native_ui_scenario(
    script: str = typer.Option(..., "--script"),
    output: str | None = typer.Option(None, "--output"),
    allow_ui: bool = typer.Option(False, "--allow-ui"),
) -> None:
    """Run an AppleScript UI scenario and optionally capture the screen."""
    from ..application import cli_compat

    _compat(lambda: cli_compat.capture_native_ui_scenario(script, output=output, allow_ui=allow_ui))


@app.command("trace-dylib-resolution")
def trace_dylib_resolution(
    path: str = typer.Argument(...),
    args: list[str] = typer.Option([], "--arg"),
    timeout: float = typer.Option(30.0, "--timeout"),
    allow_execute: bool = typer.Option(False, "--allow-execute"),
) -> None:
    """Run a target with DYLD_PRINT_LIBRARIES and capture resolution."""
    from ..application import cli_compat

    _compat(
        lambda: cli_compat.trace_dylib_resolution(
            path, allow_execute=allow_execute, args=list(args), timeout=timeout
        )
    )


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
    view: str = typer.Option(
        "summary",
        "--view",
        help="summary | record | page | environment-manifest | javascript-facts | javascript | managed | managed-members | desktop-application",
    ),
    offset: int = typer.Option(0, "--offset"),
    limit: int = typer.Option(64, "--limit"),
    paths: list[str] = typer.Option([], "--path"),
    property_keys: list[str] = typer.Option([], "--property-key"),
    evidence_id: str | None = typer.Option(None, "--evidence-id"),
    collection: str | None = typer.Option(None, "--collection"),
) -> None:
    """Project a saved Evidence record or bundle."""
    projected = load_view(
        source,
        view,
        offset=offset,
        limit=limit,
        paths=list(paths) or None,
        property_keys=list(property_keys) or None,
        evidence_id=evidence_id,
        collection=collection,
        budget_bytes=AppConfig().mcp_max_response_bytes,
    )
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
def mcp(
    transport: str = typer.Option("stdio", "--transport", help="stdio or streamable-http."),
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
    path: str = typer.Option("/mcp", "--path", help="Streamable HTTP endpoint path."),
) -> None:
    """Run the MCP server over stdio or opt-in streamable HTTP."""
    from ..server.app import run_mcp_http_server, run_mcp_server

    if transport not in ("stdio", "streamable-http"):
        fail(
            AnalysisInputError(
                operation="mcp",
                message="transport must be stdio or streamable-http",
            )
        )
    session, config = _session()
    if transport == "stdio":
        run_mcp_server(session, config)
    else:
        run_mcp_http_server(session, config, host=host, port=port, path=path)


@app.command("environment-export")
def environment_export(
    manifest: str = typer.Argument(..., help="environment-manifest Evidence JSON."),
    evidence: str = typer.Argument(..., help="Parent capture Evidence JSON."),
    directory: str = typer.Argument(..., help="New bundle directory."),
    name: str | None = typer.Option(None, "--name"),
    package_tarball: str | None = typer.Option(None, "--package-tarball"),
) -> None:
    """Export an agent environment bundle from manifest and capture Evidence."""
    from ..application.environment.bundle import write_environment_bundle
    from ..application.environment.workflow import prepare_environment

    package = (
        {"kind": "tarball", "path": package_tarball}
        if package_tarball
        else {"kind": "registry", "specifier": "rea-agents"}
    )
    prepared = prepare_environment(
        _read_json(manifest), _read_json(evidence), name=name, package_source=package
    )
    if not prepared.ok:
        fail(prepared.error)
    written = write_environment_bundle(
        prepared.value.bundle,
        directory,
        manifest_bytes=Path(manifest).read_bytes(),
        evidence_bytes=Path(evidence).read_bytes(),
        package_tarball=package_tarball,
    )
    if not written.ok:
        fail(written.error)
    emit_json(
        {
            "status": "exported",
            "directory": str(Path(directory).expanduser()),
            "name": prepared.value.bundle.name,
            "tool_count": prepared.value.bundle.tool_count,
            "state": prepared.value.bundle.state,
            "files": written.value,
        }
    )


@app.command("environment-serve")
def environment_serve(
    manifest: str = typer.Argument(..., help="environment-manifest Evidence JSON."),
    evidence: str = typer.Argument(..., help="Parent capture Evidence JSON."),
    replay_only: bool = typer.Option(False, "--replay-only"),
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(18765, "--port"),
) -> None:
    """Serve an agent environment over streamable HTTP."""
    from ..application.environment.serve import serve_environment
    from ..application.environment.workflow import prepare_environment

    prepared = prepare_environment(_read_json(manifest), _read_json(evidence))
    if not prepared.ok:
        fail(prepared.error)
    serve_environment(
        prepared.value.source,
        name=prepared.value.bundle.name,
        host=host,
        port=port,
        store=None if replay_only else prepared.value.store,
    )


@app.command("environment-compare")
def environment_compare(
    manifest: str = typer.Argument(..., help="environment-manifest Evidence JSON."),
    evidence: str = typer.Argument(..., help="Parent capture Evidence JSON."),
    probe: list[str] = typer.Option(..., "--probe", help="Probe capture Evidence JSON."),
) -> None:
    """Compare replay answers with one or more probe captures."""
    from ..application.environment.compare import compare_environment
    from ..application.environment.source import load_environment_source, load_probe_exchanges

    loaded = load_environment_source(_read_json(manifest), _read_json(evidence))
    if not loaded.ok:
        fail(loaded.error)
    rows = []
    for path in probe:
        rows.extend(load_probe_exchanges(_read_json(path)))
    emit_json(compare_environment(loaded.value, rows))


@app.command(
    "upstream",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def upstream(ctx: typer.Context, args: list[str] = typer.Argument(None)) -> None:
    """Run the caller-installed upstream Node CLI for features not yet ported."""
    import subprocess

    root = os.environ.get("REA_UPSTREAM_CLI")
    if not root:
        candidate = (
            Path(__file__).resolve().parents[3]
            / "vendor"
            / "tools"
            / "rea-upstream-node"
            / "node_modules"
            / "rea-agents"
        )
        if (candidate / "scripts" / "rea.mjs").is_file():
            root = str(candidate)
    if not root:
        fail(
            AnalysisInputError(
                operation="upstream",
                message="Set REA_UPSTREAM_CLI to an installed rea-agents package directory.",
            )
        )
    script = Path(root) / "scripts" / "rea.mjs"
    if not script.is_file():
        fail(AnalysisInputError(operation="upstream", message=f"upstream CLI not found: {script}"))
    command = list(args) if args else list(ctx.args)
    try:
        proc = subprocess.run(["node", str(script), *command], check=False)
    except OSError as cause:
        fail(AnalysisInputError(operation="upstream", message=str(cause)))
    raise typer.Exit(code=proc.returncode)


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
def doctor(
    required: str | None = typer.Option(
        None, "--required", help="Comma-separated provider ids required for this check."
    ),
    profile: str | None = typer.Option(
        None, "--profile", help="Readiness profile: core, powerbi, android or web."
    ),
    strict: bool = typer.Option(
        False, "--strict", help="Exit non-zero when required providers are missing."
    ),
) -> None:
    """Report provider and external-tool readiness."""
    required_ids = (
        [item.strip() for item in required.split(",") if item.strip()] if required else None
    )
    report = doctor_report(build_providers(), required=required_ids, profile=profile)
    emit_json(report)
    if strict and not report["healthy_required"]:
        raise typer.Exit(code=1)


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


@app.command("completions")
def completions(
    shell: str = typer.Argument(..., help="bash, zsh, fish or powershell."),
) -> None:
    """Generate a shell completion script."""
    import click.shell_completion
    import typer.main

    completion_class = click.shell_completion.get_completion_class(shell.lower())
    if completion_class is None:
        typer.echo(f"unsupported shell: {shell}", err=True)
        raise typer.Exit(2)
    command = cast("Any", typer.main.get_command(app))
    completion = completion_class(command, {}, "rea", "_REA_COMPLETE")
    typer.echo(completion.source())
