"""CLI and MCP must agree across the ``rea_mcp`` implementation and its aliases."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.e2e.harness import mcp_client, run_cli

pytestmark = pytest.mark.acceptance

MODULES = ["rea_mcp", "rea", "rea_python"]
TOOL_COUNT = 265


@pytest.mark.parametrize("module", MODULES)
def test_cli_module_aliases(module: str, elf_file: Path) -> None:
    providers = run_cli(["providers"], module=module)
    assert providers.returncode == 0, providers.stderr
    assert json.loads(providers.stdout)["providers"]

    inspect = run_cli(["inspect-binary-layout", str(elf_file)], module=module)
    assert inspect.returncode == 0, inspect.stderr
    assert json.loads(inspect.stdout)["evidence_id"].startswith("ev_")


async def test_mcp_module_alias_parity() -> None:
    tool_sets = []
    for module in MODULES:
        async with mcp_client(module) as client:
            tool_sets.append(await client.list_tools())
    assert tool_sets[0] == tool_sets[1] == tool_sets[2]
    assert len(tool_sets[0]) == TOOL_COUNT


@pytest.mark.parametrize("module", ["rea", "rea_python"])
async def test_mcp_alias_call(module: str, elf_file: Path) -> None:
    async with mcp_client(module) as client:
        opened = await client.call("open_binary", {"path": str(elf_file)})
        assert opened["open"] is True
        evidence = await client.call("inspect_binary_layout", {})
        assert evidence["evidence_id"].startswith("ev_")
