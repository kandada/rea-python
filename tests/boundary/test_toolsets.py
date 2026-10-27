from __future__ import annotations

import asyncio
import json
from pathlib import Path

from rea_mcp.application.setup import client_for_path, write_registration
from rea_mcp.composition.factories import create_binary_session
from rea_mcp.config.settings import AppConfig
from rea_mcp.server.app import build_mcp_server
from rea_mcp.server.toolsets import toolset_filter


def _catalog(toolset: str):
    config = AppConfig().model_copy(update={"mcp_toolset": toolset, "mcp_client": "minimal"})
    server = build_mcp_server(create_binary_session(config), config)
    return asyncio.run(server.list_tools())


def test_core_catalog_is_small_and_contains_task_entrypoints() -> None:
    core = _catalog("core")
    names = {tool.name for tool in core}
    assert len(core) <= 25
    assert {"open_binary", "inspect_artifact", "triage", "decompile", "evidence_export"} <= names
    full = _catalog("full")
    assert len(full) == 266
    assert len(core) < len(full) // 5


def test_domain_toolsets_are_bounded() -> None:
    for name in ("native", "web", "android", "managed", "evidence", "external"):
        tools = _catalog(name)
        assert 15 <= len(tools) < 266, name
    web = {tool.name for tool in _catalog("web")}
    assert "inspect_web_page" in web
    assert "decompile_android_class" not in web


def test_toolset_filter_can_hide_unavailable_contract_operations() -> None:
    predicate = toolset_filter(
        "core",
        client="minimal",
        available_operations={"inspect_binary_layout"},
    )
    assert predicate("inspect_binary_layout")
    assert predicate("open_binary")
    assert not predicate("decompile")


def test_opencode_setup_uses_mcp_local_shape(tmp_path: Path) -> None:
    assert client_for_path(tmp_path / "opencode.json") == "opencode"
    config = tmp_path / "opencode.json"
    config.write_text(
        json.dumps({"theme": "dark", "mcp": {"other": {"type": "local", "command": ["x"]}}}),
        encoding="utf-8",
    )
    written = write_registration(str(config))
    assert written.ok
    data = json.loads(config.read_text(encoding="utf-8"))
    assert data["theme"] == "dark"
    assert data["mcp"]["other"]["type"] == "local"
    server = data["mcp"]["rea"]
    assert server["type"] == "local"
    assert server["environment"]["REA_MCP_TOOLSET"] == "core"
    assert server["environment"]["REA_MCP_CLIENT"] == "opencode"


def test_skill_is_routing_sized() -> None:
    skill = Path("rea_mcp/data/skill.md").read_text(encoding="utf-8")
    assert len(skill.encode()) >= 8000
    assert "rea triage" in skill
    assert "--toolset core" in skill
    assert "OpenCode" in skill


def test_setup_plan_and_write_all_use_toolset_and_opencode_shape(tmp_path: Path) -> None:
    from rea_mcp.application.setup import _strip_jsonc, setup_plan, write_all_registrations

    plan = setup_plan(toolset="web", client="opencode")
    assert plan["toolset"] == "web"
    assert "mcp" in plan["server"]
    written = write_all_registrations(str(tmp_path / "clients"), toolset="full")
    assert written.ok
    # write_all uses the current user's expanded path; find it instead of assuming a name.
    candidates = list((tmp_path / "clients").rglob("opencode.json"))
    assert candidates
    data = json.loads(_strip_jsonc(candidates[0].read_text(encoding="utf-8")))
    assert data["mcp"]["rea"]["environment"]["REA_MCP_TOOLSET"] == "full"


def test_available_only_build_filters_contract_tools(monkeypatch) -> None:
    import rea_mcp.server.app as server_app

    class Capability:
        operation = "inspect_binary_layout"
        available = True

    class Provider:
        def capabilities(self):
            return (Capability(),)

    monkeypatch.setattr(server_app, "build_providers", lambda: [Provider()])
    config = AppConfig().model_copy(
        update={
            "mcp_toolset": "full",
            "mcp_client": "minimal",
            "mcp_available_only": True,
        }
    )
    server = build_mcp_server(create_binary_session(config), config)
    names = {tool.name for tool in asyncio.run(server.list_tools())}
    assert "inspect_binary_layout" in names
    assert "binary_session" in names
    assert "decompile" not in names
