"""End-to-end MCP tests: a real stdio client drives the real server."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.e2e.harness import mcp_client

pytestmark = pytest.mark.mcp


async def test_lists_full_tool_catalog() -> None:
    async with mcp_client() as client:
        tools = await client.list_tools()
    assert len(tools) == 266
    assert {"open_binary", "inspect_binary_layout", "doctor", "compare_evidence"} <= set(tools)


async def test_open_inspect_close_lifecycle(elf_file: Path) -> None:
    async with mcp_client() as client:
        opened = await client.call("open_binary", {"path": str(elf_file)})
        assert opened["open"] is True
        assert opened["target"]["format"] == "elf"

        status = await client.call("binary_session", {})
        assert status["open"] is True
        assert any(p["id"] == "binary-layout" for p in status["bound_providers"])

        evidence = await client.call("inspect_binary_layout", {})
        assert evidence["evidence_id"].startswith("ev_")
        assert evidence["normalized_result"]["format"] == "elf"

        closed = await client.call("close_binary", {})
        assert closed["open"] is False


async def test_every_builtin_inspection(
    elf_file: Path,
    go_file: Path,
    rust_file: Path,
    pe_clr_file: Path,
    sqlite_file: Path,
    zip_file: Path,
    apk_file: Path,
    flutter_apk_file: Path,
    wasm_file: Path,
    plist_file: Path,
    source_dir: Path,
    har_file: Path,
    hap_file: Path,
    js_dir: Path,
    keyed_archive_file: Path,
    pe_resources_file: Path,
) -> None:
    cases = [
        ("inspect_binary_layout", elf_file, {}),
        ("inspect_go_binary", go_file, {}),
        ("inspect_rust_binary", rust_file, {}),
        ("inspect_managed_artifact", pe_clr_file, {}),
        ("inspect_managed_members", pe_clr_file, {}),
        ("inspect_sqlite_database", sqlite_file, {"table": "users", "row_limit": 1}),
        ("inspect_artifact", zip_file, {}),
        ("inspect_android_package", apk_file, {}),
        ("identify_flutter_build", flutter_apk_file, {}),
        ("inspect_wasm_artifact", wasm_file, {}),
        ("inspect_plist", plist_file, {}),
        ("import_reference_source", source_dir, {}),
        ("inspect_network_capture", har_file, {}),
        ("inspect_harmony_package", hap_file, {}),
        ("analyze_javascript_application", js_dir, {}),
        ("inspect_keyed_archive", keyed_archive_file, {}),
        ("inspect_pe_resources", pe_resources_file, {}),
    ]
    async with mcp_client() as client:
        for tool, target, extra in cases:
            await client.call("open_binary", {"path": str(target)})
            payload = await client.call(tool, extra)
            assert payload["evidence_id"].startswith("ev_"), tool


async def test_setup_and_update_tools(tmp_path: Path) -> None:
    async with mcp_client() as client:
        plan = await client.call("setup", {})
        assert "server" in plan
        destination = tmp_path / "mcp.json"
        written = await client.call("setup", {"path": str(destination)})
        assert destination.is_file()
        assert written["written"] == str(destination)
        update = await client.call("update", {})
        assert update["current_version"]


async def test_evidence_export_import_round_trip(elf_file: Path, tmp_path: Path) -> None:
    destination = tmp_path / "bundle.json"
    async with mcp_client() as client:
        await client.call("open_binary", {"path": str(elf_file)})
        await client.call("inspect_binary_layout", {})
        exported = await client.call("evidence_export", {"path": str(destination)})
        assert exported["record_count"] == 1
        imported = await client.call("evidence_import", {"path": str(destination)})
        assert imported["imported"] is True
        assert imported["delta"]["records_added"] == 0  # same session already has it


async def test_compare_evidence_tool(elf_file: Path, tmp_path: Path) -> None:
    async with mcp_client() as client:
        await client.call("open_binary", {"path": str(elf_file)})
        evidence = await client.call("inspect_binary_layout", {})
        left = tmp_path / "l.json"
        right = tmp_path / "r.json"
        left.write_text(json.dumps(evidence), encoding="utf-8")
        right.write_text(json.dumps(evidence), encoding="utf-8")
        comparison = await client.call("compare_evidence", {"left": str(left), "right": str(right)})
        assert comparison["status"] == "unchanged"


async def test_capture_process_and_doctor() -> None:
    import sys

    async with mcp_client() as client:
        captured = await client.call(
            "capture_process", {"command": [sys.executable, "-c", "print('mcp-e2e')"]}
        )
        assert captured["stdout"].strip() == "mcp-e2e"
        doctor = await client.call("doctor", {})
        assert doctor["provider_count"] >= 16


async def test_inspect_without_open_is_error() -> None:
    async with mcp_client() as client:
        result = await client.call_raw("inspect_binary_layout", {})
        assert result.isError is True
        text = result.content[0].text
        assert "NO_TARGET_OPEN" in text


async def test_sequential_targets(elf_file: Path, sqlite_file: Path) -> None:
    async with mcp_client() as client:
        await client.call("open_binary", {"path": str(elf_file)})
        assert (await client.call("inspect_binary_layout", {}))["normalized_result"][
            "format"
        ] == "elf"
        await client.call("open_binary", {"path": str(sqlite_file)})
        assert (await client.call("inspect_sqlite_database", {}))["normalized_result"]["tables"]


async def test_unknowns_round_trip(elf_file: Path) -> None:
    async with mcp_client() as client:
        await client.call("open_binary", {"path": str(elf_file)})
        recorded = await client.call(
            "record_unknown", {"question": "Is it reachable?", "domain": "reachability"}
        )
        unknown_id = recorded["unknown_id"]
        listed = await client.call("list_unknowns", {})
        assert any(item["unknown_id"] == unknown_id for item in listed["unknowns"])
        updated = await client.call(
            "update_unknown", {"unknown_id": unknown_id, "status": "investigating"}
        )
        assert updated["revision"] == 2


async def test_snapshot_round_trip(elf_file: Path, tmp_path: Path) -> None:
    destination = tmp_path / "snap.json"
    async with mcp_client() as client:
        exported = await client.call(
            "snapshot_export", {"path": str(elf_file), "out": str(destination)}
        )
        assert destination.is_file()
        assert exported["path"] == str(destination)
        imported = await client.call(
            "snapshot_import", {"path": str(elf_file), "source": str(destination)}
        )
        assert imported["imported"] is True


async def test_schema_exposes_kuna_raw_and_electron_launch_arguments() -> None:
    async with mcp_client() as client:
        tools = {tool.name: tool for tool in await client.tool_models()}
    for name in ("kuna_decompile", "list_procedures", "list_strings", "xrefs"):
        properties = tools[name].inputSchema["properties"]
        assert {"raw_image", "target", "base", "entry"} <= set(properties)
    electron = tools["capture_electron_scenario"].inputSchema["properties"]
    assert {"app", "executable", "port", "launch_args", "launch_timeout"} <= set(electron)
