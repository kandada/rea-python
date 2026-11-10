from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, cast

from rea_mcp.application.setup import (
    _sandbox_relative,
    client_for_path,
    write_registration,
)
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
    assert len(full) == 292
    assert len(core) < len(full) // 5


def test_domain_toolsets_are_bounded() -> None:
    for name in ("native", "web", "android", "managed", "evidence", "external"):
        tools = _catalog(name)
        assert 15 <= len(tools) < 292, name
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


def test_sandbox_relative_drops_windows_drive_anchor() -> None:
    relative = _sandbox_relative(
        "C:/Users/demo/.config/opencode/opencode.json", Path("C:/Users/demo")
    )
    assert relative == Path(".config/opencode/opencode.json")


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
    candidates = list((tmp_path / "clients").rglob("opencode.json"))
    assert candidates, written.value
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


def test_clean_room_filter_excludes_inside_tools() -> None:
    from rea_mcp.server.toolsets import clean_room_filter

    assert clean_room_filter("project_show")
    assert clean_room_filter("craft_check")
    assert not clean_room_filter("decompile")
    assert not clean_room_filter("inspect_binary_layout")


def test_registry_and_mode_metadata() -> None:
    from rea_mcp.application.project.service import run as project_run
    from rea_mcp.application.project.store import ProjectStore
    from rea_mcp.domain.mode import allows
    from rea_mcp.tooling.registry import REGISTRY

    spec = REGISTRY.get("craft_run")
    assert spec is not None and spec.toolset == "craft"
    assert REGISTRY.get("inspect_java_class") is not None
    assert allows("clean_room", "target_outside")
    assert not allows("clean_room", "target_inside")
    assert ProjectStore.__name__ == "ProjectStore"
    assert callable(project_run)


def test_registry_covers_every_mcp_and_cli_name() -> None:
    import typer.main

    from rea_mcp.cli.app import app as cli_app
    from rea_mcp.tooling.registry import REGISTRY

    config = AppConfig().model_copy(update={"mcp_toolset": "full", "mcp_client": "minimal"})
    server = build_mcp_server(create_binary_session(config), config)
    mcp_names = {tool.name for tool in asyncio.run(server.list_tools())}
    assert mcp_names <= {tool.id for tool in REGISTRY.all()}
    commands = set(cast("Any", typer.main.get_command(cli_app)).commands)
    assert commands <= {tool.cli_name for tool in REGISTRY.all() if tool.cli_name}


def test_invalid_toolset_name_is_rejected() -> None:
    import pytest

    from rea_mcp.server.toolsets import resolve_toolset

    with pytest.raises(ValueError):
        resolve_toolset("not-a-toolset")


def test_freebuff_setup_path_is_known() -> None:
    from rea_mcp.application.setup import client_for_path

    assert client_for_path("~/.freebuff/mcp.json") == "generic"
