"""MCP transport interceptors: response budget, oversized-error retention, cleanup.

FastMCP handles requests internally; this module wraps the stdio transport so the
server can enforce a hard response budget at the stream boundary, retain oversized
payloads as Evidence (returning an ``evidence_reference``), stamp target-content
results as untrusted, and observe ``notifications/cancelled`` for cleanup.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import anyio
from mcp import types
from mcp.server.fastmcp import FastMCP
from mcp.server.stdio import stdio_server
from mcp.shared.message import SessionMessage

_UNTRUSTED_PROVENANCE = {"untrusted_content": True, "source": "analysis_target"}


class TransportInterceptors:
    """Stateful read/write interceptors for a single MCP stdio connection."""

    def __init__(
        self,
        *,
        budget_bytes: int,
        retain: Callable[[str, dict[str, Any]], str],
        exempt_tools: frozenset[str] | set[str] = frozenset(),
    ) -> None:
        self.budget_bytes = budget_bytes
        self._retain = retain
        self.exempt_tools = set(exempt_tools)
        self._tool_by_id: dict[Any, str] = {}
        self.retained_count = 0
        self.cancelled_count = 0

    # -- read path ---------------------------------------------------------

    def observe_incoming(self, message: SessionMessage) -> None:
        root = message.message.root
        if isinstance(root, types.JSONRPCRequest):
            name = _tool_name(root.params)
            if name:
                self._tool_by_id[root.id] = name
        elif isinstance(root, types.JSONRPCNotification) and (
            root.method == "notifications/cancelled"
        ):
            params = root.params if isinstance(root.params, dict) else {}
            request_id = params.get("requestId")
            self._tool_by_id.pop(request_id, None)
            self.cancelled_count += 1

    # -- write path --------------------------------------------------------

    def transform_outgoing(self, message: SessionMessage) -> SessionMessage:
        root = message.message.root
        if isinstance(root, types.JSONRPCResponse):
            return self._transform_response(message, root)
        if isinstance(root, types.JSONRPCError):
            return self._transform_error(message, root)
        return message

    def _transform_response(
        self, message: SessionMessage, root: types.JSONRPCResponse
    ) -> SessionMessage:
        tool = self._tool_by_id.pop(root.id, None)
        result = self._mark_untrusted(root.result, tool)
        size = _encoded_size(result)
        if size > self.budget_bytes:
            evidence_id = self._retain(tool or "tools/call", _as_payload(result))
            self.retained_count += 1
            return _error_message(
                root.id,
                code=-32001,
                message="The result exceeds the MCP response budget.",
                data={
                    "code": "RESOURCE_CONSTRAINT",
                    "tag": "AnalysisResourceConstraintError",
                    "resource": "transport",
                    "result_budget_bytes": self.budget_bytes,
                    "response_bytes_at_least": size,
                    "evidence_reference": {"kind": "retained-evidence", "evidence_id": evidence_id},
                },
            )
        if result is not root.result:
            updated = root.model_copy(update={"result": result})
            return SessionMessage(types.JSONRPCMessage(root=updated))
        return message

    def _transform_error(self, message: SessionMessage, root: types.JSONRPCError) -> SessionMessage:
        payload = root.error.data
        if payload is None or _encoded_size(payload) <= self.budget_bytes:
            return message
        evidence_id = self._retain("error", {"data": _as_payload(payload)})
        self.retained_count += 1
        return _error_message(
            root.id,
            code=root.error.code,
            message=root.error.message,
            data={
                "code": "RESOURCE_CONSTRAINT",
                "resource": "error",
                "result_budget_bytes": self.budget_bytes,
                "evidence_reference": {"kind": "retained-evidence", "evidence_id": evidence_id},
            },
        )

    def _mark_untrusted(self, result: Any, tool: str | None) -> Any:
        if tool is None or tool in self.exempt_tools or not isinstance(result, dict):
            return result
        meta = result.get("_meta")
        if isinstance(meta, dict) and "provenance" in meta:
            return result
        return {**result, "_meta": {"provenance": dict(_UNTRUSTED_PROVENANCE)}}


def _tool_name(params: Any) -> str | None:
    if isinstance(params, dict):
        name = params.get("name")
        return name if isinstance(name, str) else None
    return None


def _encoded_size(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False, default=str).encode("utf-8"))


def _as_payload(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {"value": value}


def _error_message(
    request_id: Any, *, code: int, message: str, data: dict[str, Any]
) -> SessionMessage:
    error = types.ErrorData(code=code, message=message, data=data)
    root = types.JSONRPCMessage(root=types.JSONRPCError(jsonrpc="2.0", id=request_id, error=error))
    return SessionMessage(root)


async def run_stdio_server(
    server: FastMCP,
    *,
    budget_bytes: int,
    retain: Callable[[str, dict[str, Any]], str],
    exempt_tools: frozenset[str] | set[str] = frozenset(),
) -> None:
    """Run ``server`` over stdio with the interceptor wrappers installed."""

    interceptors = TransportInterceptors(
        budget_bytes=budget_bytes, retain=retain, exempt_tools=exempt_tools
    )
    low_level = server._mcp_server
    async with stdio_server() as (read_stream, write_stream):
        incoming_tx, incoming_rx = anyio.create_memory_object_stream[Any](0)
        outgoing_tx, outgoing_rx = anyio.create_memory_object_stream[Any](0)

        async def pump_incoming() -> None:
            async with incoming_tx:
                async for item in read_stream:
                    if isinstance(item, SessionMessage):
                        interceptors.observe_incoming(item)
                    await incoming_tx.send(item)

        async def pump_outgoing() -> None:
            async with outgoing_rx:
                async for item in outgoing_rx:
                    if isinstance(item, SessionMessage):
                        item = interceptors.transform_outgoing(item)
                    await write_stream.send(item)

        async with anyio.create_task_group() as task_group:
            task_group.start_soon(pump_incoming)
            task_group.start_soon(pump_outgoing)
            await low_level.run(incoming_rx, outgoing_tx, low_level.create_initialization_options())
            task_group.cancel_scope.cancel()


__all__ = ["TransportInterceptors", "run_stdio_server"]


class HttpBudgetMiddleware:
    """Enforce the stdio byte budget on JSON streamable-HTTP responses.

    Streaming SSE responses are left to the tool-layer guards; the HTTP
    transport is opt-in and the default JSON mode covers ordinary calls.
    """

    def __init__(
        self, app: Any, *, budget_bytes: int, retain: Callable[[str, dict[str, Any]], str]
    ) -> None:
        self.app = app
        self.budget_bytes = budget_bytes
        self.retain = retain

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        started = False
        json_response = False
        sse = False
        status = 0
        headers: list[tuple[bytes, bytes]] = []
        body_parts: list[bytes] = []
        sse_buffer = b""

        async def capture(message: Any) -> None:
            nonlocal started, json_response, sse, status, headers, sse_buffer
            if message["type"] == "http.response.start":
                started = True
                status = int(message["status"])
                headers = list(message.get("headers") or [])
                content_type = dict(headers).get(b"content-type", b"").decode("latin-1").lower()
                json_response = content_type.startswith("application/json")
                sse = content_type.startswith("text/event-stream")
                if not json_response:
                    await send(message)
                return
            if message["type"] == "http.response.body":
                if json_response:
                    body_parts.append(bytes(message.get("body", b"")))
                elif sse:
                    chunk = bytes(message.get("body", b""))
                    sse_buffer += chunk
                    while b"\n" in sse_buffer:
                        line, sse_buffer = sse_buffer.split(b"\n", 1)
                        await send(
                            {
                                "type": "http.response.body",
                                "body": self._sse_line(line) + b"\n",
                                "more_body": True,
                            }
                        )
                else:
                    await send(message)

        await self.app(scope, receive, capture)
        if sse:
            if sse_buffer:
                await send(
                    {
                        "type": "http.response.body",
                        "body": self._sse_line(sse_buffer),
                        "more_body": False,
                    }
                )
            else:
                await send({"type": "http.response.body", "body": b"", "more_body": False})
            return
        if not started or not json_response:
            return
        body = b"".join(body_parts)
        if len(body) > self.budget_bytes:
            try:
                payload = json.loads(body)
            except (ValueError, UnicodeDecodeError):
                payload = None
            if isinstance(payload, dict) and "id" in payload:
                evidence_id = self.retain("mcp-http", _as_payload(payload.get("result")))
                payload = {
                    "jsonrpc": "2.0",
                    "id": payload.get("id"),
                    "error": {
                        "code": -32001,
                        "message": "The result exceeds the MCP response budget.",
                        "data": {
                            "code": "RESOURCE_CONSTRAINT",
                            "tag": "AnalysisResourceConstraintError",
                            "resource": "transport",
                            "result_budget_bytes": self.budget_bytes,
                            "response_bytes_at_least": len(body),
                            "evidence_reference": {
                                "kind": "retained-evidence",
                                "evidence_id": evidence_id,
                            },
                        },
                    },
                }
                body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = [
            (key, value)
            for key, value in headers
            if key.lower() not in (b"content-length", b"transfer-encoding")
        ]
        headers.append((b"content-length", str(len(body)).encode("ascii")))
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body, "more_body": False})

    def _sse_line(self, line: bytes) -> bytes:
        if not line.startswith(b"data: "):
            return line
        try:
            payload = json.loads(line[6:])
        except (ValueError, UnicodeDecodeError):
            return line
        if not isinstance(payload, dict) or "id" not in payload:
            return line
        if _encoded_size(payload) <= self.budget_bytes:
            return line
        evidence_id = self.retain("mcp-http-sse", _as_payload(payload.get("result")))
        replacement = {
            "jsonrpc": "2.0",
            "id": payload.get("id"),
            "error": {
                "code": -32001,
                "message": "The result exceeds the MCP response budget.",
                "data": {
                    "code": "RESOURCE_CONSTRAINT",
                    "tag": "AnalysisResourceConstraintError",
                    "resource": "transport",
                    "result_budget_bytes": self.budget_bytes,
                    "response_bytes_at_least": _encoded_size(payload),
                    "evidence_reference": {
                        "kind": "retained-evidence",
                        "evidence_id": evidence_id,
                    },
                },
            },
        }
        return b"data: " + json.dumps(replacement, ensure_ascii=False).encode("utf-8")


__all__ = ["HttpBudgetMiddleware", "TransportInterceptors", "run_stdio_server"]
