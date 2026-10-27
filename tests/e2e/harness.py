"""End-to-end harnesses: real CLI subprocesses and a real stdio MCP client."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

REPO_ROOT = Path(__file__).resolve().parents[2]


def _env() -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT)
    env.setdefault("REA_MCP_TOOLSET", "full")
    return env


# -- CLI --------------------------------------------------------------------


def run_cli(
    args: list[str],
    *,
    module: str = "rea_mcp",
    cwd: Path | None = None,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", module, *args],
        cwd=str(cwd or REPO_ROOT),
        env=_env(),
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def cli_json(args: list[str], *, module: str = "rea_mcp", timeout: int = 120) -> dict[str, Any]:
    proc = run_cli(args, module=module, timeout=timeout)
    assert proc.returncode == 0, (
        f"CLI failed ({proc.returncode}): {proc.stderr}\nstdout={proc.stdout}"
    )
    return json.loads(proc.stdout)


# -- MCP --------------------------------------------------------------------


class McpClient:
    def __init__(self, session: ClientSession) -> None:
        self._session = session

    async def list_tools(self) -> list[str]:
        listed = await self._session.list_tools()
        return sorted(tool.name for tool in listed.tools)

    async def tool_models(self) -> list[Any]:
        listed = await self._session.list_tools()
        return list(listed.tools)

    async def call_raw(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        return await self._session.call_tool(name, arguments or {})

    async def call(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        result = await self.call_raw(name, arguments)
        assert result.isError is not True, f"{name} returned isError: {_text(result)}"
        return _structured(result)


@asynccontextmanager
async def mcp_client(module: str = "rea_mcp") -> AsyncIterator[McpClient]:
    params = StdioServerParameters(command=sys.executable, args=["-m", module, "mcp"], env=_env())
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        yield McpClient(session)


def _text(result: Any) -> str:
    for block in getattr(result, "content", []) or []:
        text = getattr(block, "text", None)
        if text is not None:
            return text
    return ""


def _structured(result: Any) -> dict[str, Any]:
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        return structured
    text = _text(result)
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return {"text": text}
    return parsed if isinstance(parsed, dict) else {"value": parsed}
