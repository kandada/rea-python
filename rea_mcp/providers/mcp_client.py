"""Minimal MCP client for caller-supplied IDA/JEB MCP servers.

Supports stdio registrations (``command``/``args``/``env``) and streamable HTTP
endpoints. Connections are opened per operation so a long-lived REA process does
not hold the upstream engine open between calls.
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client

_DEFAULT_JEB_URL = "http://127.0.0.1:8425/mcp"


class McpClientError(RuntimeError):
    """The upstream MCP server failed or returned an error result."""


@dataclass
class McpServerConfig:
    transport: str
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None
    headers: dict[str, str] = field(default_factory=dict)


def _registration(payload: Any, key: str) -> McpServerConfig | None:
    if not isinstance(payload, dict):
        return None
    servers = payload.get("mcpServers")
    server: Any = servers.get(key) if isinstance(servers, dict) else None
    if server is None and ("url" in payload or "command" in payload):
        server = payload
    if not isinstance(server, dict):
        return None
    if "url" in server:
        return McpServerConfig(
            "http",
            url=str(server["url"]),
            headers={str(k): str(v) for k, v in (server.get("headers") or {}).items()},
        )
    if "command" in server:
        return McpServerConfig(
            "stdio",
            command=str(server["command"]),
            args=[str(item) for item in (server.get("args") or [])],
            env={str(k): str(v) for k, v in (server.get("env") or {}).items()},
        )
    return None


def load_ida_config() -> McpServerConfig | None:
    path = os.environ.get("REA_IDA_MCP_CONFIG")
    if path:
        try:
            payload = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return _registration(payload, "ida-pro-mcp")
    url = os.environ.get("REA_IDA_MCP_URL")
    if url:
        return McpServerConfig("http", url=url)
    command = os.environ.get("REA_IDA_MCP_COMMAND")
    if command:
        parts = shlex.split(command)
        return McpServerConfig("stdio", command=parts[0], args=parts[1:])
    return None


def load_jeb_config() -> McpServerConfig | None:
    path = os.environ.get("REA_JEB_MCP_CONFIG")
    if path:
        try:
            payload = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        config = _registration(payload, "jeb-mcp")
        if config is not None:
            return config
    return McpServerConfig("http", url=os.environ.get("REA_JEB_MCP_URL") or _DEFAULT_JEB_URL)


def jeb_reachable(timeout: float = 0.4) -> bool:
    import socket
    from urllib.parse import urlparse

    config = load_jeb_config()
    if config is None or config.transport != "http" or not config.url:
        return False
    parsed = urlparse(config.url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class McpClient:
    def __init__(self, config: McpServerConfig, *, timeout: float = 120.0) -> None:
        self.config = config
        self.timeout = timeout

    def call(
        self,
        tool: str,
        arguments: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> Any:
        return asyncio.run(self._call(tool, arguments or {}, timeout=timeout or self.timeout))

    async def _call(self, tool: str, arguments: dict[str, Any], *, timeout: float) -> Any:
        async with self._session(timeout) as session:
            result = await session.call_tool(
                tool, arguments, read_timeout_seconds=timedelta(seconds=timeout)
            )
            return _decode(result)

    @asynccontextmanager
    async def _session(self, timeout: float):  # type: ignore[no-untyped-def]
        if self.config.transport == "stdio":
            if not self.config.command:
                raise McpClientError("stdio MCP registration has no command")
            parameters = StdioServerParameters(
                command=self.config.command,
                args=self.config.args,
                env={**os.environ, **self.config.env},
            )
            async with (
                stdio_client(parameters) as (read, write),
                ClientSession(read, write) as session,
            ):
                await session.initialize()
                yield session
        else:
            if not self.config.url:
                raise McpClientError("HTTP MCP registration has no url")
            async with (
                streamablehttp_client(
                    self.config.url,
                    headers=self.config.headers,
                    timeout=timeout,
                ) as (read, write, _get_session_id),
                ClientSession(read, write) as session,
            ):
                await session.initialize()
                yield session


def _decode(result: Any) -> Any:
    if getattr(result, "isError", False):
        raise McpClientError(_text(result) or "upstream MCP tool failed")
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        return structured
    text = _text(result)
    if text:
        try:
            return json.loads(text)
        except ValueError:
            return {"text": text}
    return {}


def _text(result: Any) -> str:
    blocks = getattr(result, "content", None) or []
    parts = [
        block.text
        for block in blocks
        if getattr(block, "type", None) == "text" and getattr(block, "text", None)
    ]
    return "\n".join(parts)


__all__ = [
    "McpClient",
    "McpClientError",
    "McpServerConfig",
    "jeb_reachable",
    "load_ida_config",
    "load_jeb_config",
]
