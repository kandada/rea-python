import asyncio
import json
from pathlib import Path
from typing import Any

from rea_mcp.composition.factories import create_binary_session
from rea_mcp.config.settings import AppConfig
from rea_mcp.server.app import build_mcp_server


async def _call(server: Any, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    result = await server.call_tool(name, arguments)
    if isinstance(result, tuple):  # (content, structured) on some SDK versions
        result = result[1] if isinstance(result[1], dict) else result[0]
    if isinstance(result, dict):
        return result
    for block in result:
        text = getattr(block, "text", None)
        if text:
            return json.loads(text)
    raise AssertionError(f"No structured result for {name}")


async def test_open_and_inspect(elf_file: Path) -> None:
    server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
    opened = await _call(server, "open_binary", {"path": str(elf_file)})
    assert opened["open"] is True
    assert opened["target"]["format"] == "elf"

    evidence = await _call(server, "inspect_binary_layout", {})
    assert evidence["evidence_id"].startswith("ev_")
    assert evidence["normalized_result"]["format"] == "elf"


async def test_binary_session_reports_bound_providers(elf_file: Path) -> None:
    server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
    await _call(server, "open_binary", {"path": str(elf_file)})
    status = await _call(server, "binary_session", {})
    assert status["open"] is True
    assert any(provider["id"] == "binary-layout" for provider in status["bound_providers"])


async def test_providers_tool() -> None:
    server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
    result = await _call(server, "providers", {})
    ids = {provider["id"] for provider in result["providers"]}
    assert {"binary-layout", "go", "rust", "sqlite"} <= ids


async def test_inspect_requires_open(tmp_path: Path) -> None:
    server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
    try:
        await _call(server, "inspect_binary_layout", {})
    except Exception as cause:
        assert "NO_TARGET_OPEN" in str(cause) or "No binary" in str(cause)
    else:
        raise AssertionError("inspect without an open target should fail")


async def test_evidence_export(elf_file: Path, tmp_path: Path) -> None:
    server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
    await _call(server, "open_binary", {"path": str(elf_file)})
    await _call(server, "inspect_go_binary", {})
    destination = tmp_path / "bundle.json"
    result = await _call(server, "evidence_export", {"path": str(destination)})
    assert result["record_count"] == 1
    assert destination.is_file()


async def test_doctor_tool() -> None:
    server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
    report = await _call(server, "doctor", {})
    assert "providers" in report
    assert any(entry["id"] == "binary-layout" for entry in report["providers"])


async def test_capture_process_tool() -> None:
    import sys

    server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
    result = await _call(
        server, "capture_process", {"command": [sys.executable, "-c", "print('hi')"]}
    )
    assert result["stdout"].strip() == "hi"


async def test_compare_evidence_tool(elf_file: Path, tmp_path: Path) -> None:
    server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
    await _call(server, "open_binary", {"path": str(elf_file)})
    evidence = await _call(server, "inspect_binary_layout", {})
    left = tmp_path / "left.json"
    right = tmp_path / "right.json"
    left.write_text(json.dumps(evidence), encoding="utf-8")
    right.write_text(json.dumps(evidence), encoding="utf-8")
    comparison = await _call(server, "compare_evidence", {"left": str(left), "right": str(right)})
    assert comparison["status"] == "unchanged"


async def test_target_content_tools_marked_untrusted() -> None:
    server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
    tools = {tool.name: tool for tool in await server.list_tools()}
    marked = tools["inspect_binary_layout"].meta
    assert marked is not None
    assert marked["provenance"]["untrusted_content"] is True
    assert tools["binary_session"].meta is None or "provenance" not in (
        tools["binary_session"].meta or {}
    )


async def test_response_budget_is_enforced(monkeypatch: Any, big_plist_file: Path) -> None:
    class _TightBudget:
        mcp_max_response_bytes = 1024

    monkeypatch.setattr("rea_mcp.server.app.AppConfig", lambda: _TightBudget())
    server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
    await _call(server, "open_binary", {"path": str(big_plist_file)})
    try:
        await _call(server, "inspect_plist", {})
    except Exception as cause:  # ToolError text carries the structured payload
        assert "RESOURCE_CONSTRAINT" in str(cause)
    else:
        raise AssertionError("an oversized result should be rejected")


def test_setup_install_skill_and_write_all(tmp_path: Path) -> None:
    from rea_mcp.application.setup import (
        KNOWN_CLIENT_CONFIGS,
        install_skill,
        write_all_registrations,
    )

    installed = install_skill(str(tmp_path / "skills"))
    assert installed.ok
    assert Path(installed.value["installed"]).is_file()

    written = write_all_registrations(str(tmp_path / "clients"))
    assert written.ok
    assert len(written.value["written"]) == len(KNOWN_CLIENT_CONFIGS)


async def test_runtime_tool_runs_without_open_target(monkeypatch: Any, tmp_path: Path) -> None:
    import http.server
    import threading

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/json/version":
                body: object = {"Browser": "Chrome/120"}
            else:
                body = [{"type": "page", "url": "https://example.com/"}]
            payload = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args: object) -> None:
            del args

    http_server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=http_server.serve_forever, daemon=True)
    thread.start()
    try:
        endpoint = f"http://127.0.0.1:{http_server.server_port}"
        server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
        result = await _call(server, "inspect_cdp_targets", {"endpoint": endpoint})
        assert result["target_count"] == 1
        assert result["browser"] == "Chrome/120"
    finally:
        http_server.shutdown()
        thread.join(timeout=5)


def test_client_preset_compacts_schemas() -> None:
    config = AppConfig(mcp_client="vscode")
    server = build_mcp_server(create_binary_session(config), config)
    tools = asyncio.run(server.list_tools())
    layout = next(tool for tool in tools if tool.name == "inspect_binary_layout")
    assert layout.outputSchema is None
    assert "properties" in layout.inputSchema
    assert "description" not in json.dumps(layout.inputSchema)


async def test_compat_alias_tools_registered() -> None:
    server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
    names = {tool.name for tool in await server.list_tools()}
    assert {
        "binary_overview",
        "analyze_function",
        "capture_process_scenario",
        "compare_artifacts",
        "export_evidence_bundle",
        "import_evidence_bundle",
        "inspect_web_network_capture",
    } <= names


def test_setup_merges_existing_client_config(tmp_path: Path) -> None:
    from rea_mcp.application.setup import write_registration

    config = tmp_path / "config.json"
    config.write_text(
        json.dumps({"theme": "dark", "mcpServers": {"other": {"command": "x"}}}),
        encoding="utf-8",
    )
    written = write_registration(str(config))
    assert written.ok
    data = json.loads(config.read_text(encoding="utf-8"))
    assert data["theme"] == "dark"
    assert data["mcpServers"]["other"]["command"] == "x"
    assert data["mcpServers"]["rea-mcp"]["args"] == ["-m", "rea_mcp", "mcp"]


def test_setup_merges_jsonc_config(tmp_path: Path) -> None:
    from rea_mcp.application.setup import _strip_jsonc, write_registration

    config = tmp_path / "config.jsonc"
    config.write_text(
        """
        {
          // existing client servers
          "mcpServers": {
            "other": {"command": "x"},
          },
          "theme": "dark",
        }
        """,
        encoding="utf-8",
    )
    written = write_registration(str(config))
    assert written.ok
    data = json.loads(_strip_jsonc(config.read_text(encoding="utf-8")))
    assert data["theme"] == "dark"
    assert data["mcpServers"]["other"]["command"] == "x"
    assert "rea-mcp" in data["mcpServers"]
    assert (tmp_path / "config.jsonc.bak").is_file()


def test_setup_edits_last_duplicate_member(tmp_path: Path) -> None:
    from rea_mcp.application.setup import _strip_jsonc, write_registration

    config = tmp_path / "config.jsonc"
    config.write_text(
        """
        {
          // first member is shadowed by the second
          "mcpServers": {"first": {"command": "a"}},
          "mcpServers": {"second": {"command": "b"}},
        }
        """,
        encoding="utf-8",
    )
    written = write_registration(str(config))
    assert written.ok
    assert written.value["edited_last_duplicate"] is True
    text = config.read_text(encoding="utf-8")
    assert '"first"' in text  # earlier duplicate preserved
    data = json.loads(_strip_jsonc(text))
    assert data["mcpServers"]["second"]["command"] == "b"
    assert "rea-mcp" in data["mcpServers"]
