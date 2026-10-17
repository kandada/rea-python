import asyncio
import os
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

pytestmark = pytest.mark.slow

REPO_ROOT = Path(__file__).resolve().parents[2]


async def _list_tools() -> list[str]:
    env = dict(os.environ, PYTHONPATH=str(REPO_ROOT))
    params = StdioServerParameters(command=sys.executable, args=["-m", "rea_mcp", "mcp"], env=env)
    async with (
        stdio_client(params) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        tools = await session.list_tools()
        return sorted(tool.name for tool in tools.tools)


def test_stdio_server_lists_tools() -> None:
    names = asyncio.run(asyncio.wait_for(_list_tools(), timeout=60))
    required = {
        "open_binary",
        "inspect_binary_layout",
        "inspect_go_binary",
        "inspect_wasm_artifact",
        "analyze",
        "decompile",
        "compare_evidence",
        "capture_process",
        "doctor",
    }
    assert required <= set(names)
    assert len(names) == 232


async def _list_tools_with_tiny_budget() -> str:
    env = dict(
        os.environ,
        PYTHONPATH=str(REPO_ROOT),
        REA_MCP_MAX_RESPONSE_BYTES="1024",
    )
    params = StdioServerParameters(command=sys.executable, args=["-m", "rea_mcp", "mcp"], env=env)
    async with (
        stdio_client(params) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        try:
            await session.list_tools()
        except Exception as cause:
            return str(cause)
    return ""


def test_stdio_transport_budget_is_enforced() -> None:
    message = asyncio.run(asyncio.wait_for(_list_tools_with_tiny_budget(), timeout=60))
    assert "RESOURCE_CONSTRAINT" in message or "budget" in message.lower()
