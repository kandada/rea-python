import asyncio
import json
import os
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

pytestmark = pytest.mark.slow

REPO_ROOT = Path(__file__).resolve().parents[2]


async def _list_tools() -> list[str]:
    env = dict(os.environ, PYTHONPATH=str(REPO_ROOT), REA_MCP_TOOLSET="full")
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
    assert len(names) == 292


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


async def _call_tool_with_tiny_budget(path: str) -> str:
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
            result = await session.call_tool("inspect_binary_layout", {"path": path})
        except Exception as cause:
            error = getattr(cause, "error", None)
            data = getattr(error, "data", None)
            return json.dumps(data, default=str) if data is not None else str(cause)
        return str(result)


def test_stdio_tool_result_budget_returns_envelope() -> None:
    message = asyncio.run(asyncio.wait_for(_call_tool_with_tiny_budget(sys.executable), timeout=60))
    assert "RESOURCE_CONSTRAINT" in message
    assert "evidence_reference" in message
    assert "ev_" in message
