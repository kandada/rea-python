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
