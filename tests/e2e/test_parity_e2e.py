"""CLI and MCP must produce identical Evidence for the same operation."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.e2e.harness import cli_json, mcp_client

pytestmark = pytest.mark.acceptance


async def test_binary_layout_parity(elf_file: Path, pe_file: Path) -> None:
    for target in (elf_file, pe_file):
        cli = cli_json(["inspect-binary-layout", str(target)])
        async with mcp_client() as client:
            await client.call("open_binary", {"path": str(target)})
            mcp = await client.call("inspect_binary_layout", {})
        assert cli["evidence_id"] == mcp["evidence_id"], target


async def test_go_and_rust_parity(go_file: Path, rust_file: Path) -> None:
    go_cli = cli_json(["inspect-go-binary", str(go_file)])
    rust_cli = cli_json(["inspect-rust-binary", str(rust_file)])
    async with mcp_client() as client:
        await client.call("open_binary", {"path": str(go_file)})
        go_mcp = await client.call("inspect_go_binary", {})
        await client.call("open_binary", {"path": str(rust_file)})
        rust_mcp = await client.call("inspect_rust_binary", {})
    assert go_cli["evidence_id"] == go_mcp["evidence_id"]
    assert rust_cli["evidence_id"] == rust_mcp["evidence_id"]
