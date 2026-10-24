"""Minimal replay-oriented environment MCP server.

The full state/write/agentenv protocol is layered on this server as the state
and write components mature. It already exposes every manifest tool and a
state summary over streamable HTTP.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

from mcp.server.fastmcp import FastMCP

from .compare import compare_environment
from .coverage import environment_coverage
from .replay import replay_tool
from .source import EnvironmentSource
from .state_store import EnvironmentStateStore


def build_environment_server(
    source: EnvironmentSource,
    *,
    name: str = "environment",
    store: EnvironmentStateStore | None = None,
) -> FastMCP:
    server = FastMCP(name=name)
    for tool in source.manifest.get("tools") or []:
        tool_name = str(tool.get("name") or "")
        if not tool_name:
            continue

        parameter_names = [
            str(name)
            for name, _location in (tool.get("parameters") or {}).items()
            if str(name).isidentifier()
        ]

        def make_call(selected: str) -> Callable[..., dict[str, Any]]:
            def handler(**kwargs: Any) -> dict[str, Any]:
                answer = replay_tool(source, selected, kwargs)
                return answer.__dict__

            return handler

        call = make_call(tool_name)

        if parameter_names:
            call.__signature__ = inspect.Signature(  # type: ignore[attr-defined]
                [
                    inspect.Parameter(
                        name, inspect.Parameter.KEYWORD_ONLY, default=None, annotation=Any
                    )
                    for name in parameter_names
                ]
            )
        server.add_tool(
            call,
            name=tool_name,
            description=str(tool.get("description") or f"Replay {tool_name} from the capture."),
        )

    from starlette.requests import Request
    from starlette.responses import JSONResponse

    @server.custom_route("/.well-known/agent-env.json", methods=["GET"], include_in_schema=False)  # type: ignore[untyped-decorator]
    async def environment_card(request: Request) -> JSONResponse:
        del request
        return JSONResponse(
            {
                "name": name,
                "tools": [tool.get("name") for tool in source.manifest.get("tools") or []],
                "state": store is not None,
                "evidence_id": source.evidence_id,
            }
        )

    async def _body(request: Request) -> dict[str, Any]:
        try:
            value = await request.json()
        except Exception:
            return {}
        return value if isinstance(value, dict) else {}

    @server.custom_route("/agentenv/data/get", methods=["POST"], include_in_schema=False)  # type: ignore[untyped-decorator]
    async def environment_data_get(request: Request) -> JSONResponse:
        if store is None:
            return JSONResponse({"error": "state-not-derived"}, status_code=503)
        body = await _body(request)
        entity = store.get(str(body.get("collection") or ""), str(body.get("id") or ""))
        return JSONResponse({"entity": entity}, status_code=200 if entity is not None else 404)

    @server.custom_route("/agentenv/data/list", methods=["POST"], include_in_schema=False)  # type: ignore[untyped-decorator]
    async def environment_data_list(request: Request) -> JSONResponse:
        if store is None:
            return JSONResponse({"error": "state-not-derived"}, status_code=503)
        body = await _body(request)
        rows = store.list_entities(str(body.get("collection") or ""))
        return JSONResponse({"entities": rows, "count": len(rows)})

    @server.custom_route("/agentenv/data/merge", methods=["POST"], include_in_schema=False)  # type: ignore[untyped-decorator]
    async def environment_data_merge(request: Request) -> JSONResponse:
        if store is None:
            return JSONResponse({"error": "state-not-derived"}, status_code=503)
        from .writes import merge_entity

        body = await _body(request)
        fields = body.get("fields")
        result = merge_entity(
            store,
            str(body.get("collection") or ""),
            str(body.get("id") or ""),
            fields if isinstance(fields, dict) else {},
        )
        return JSONResponse(
            {
                "entity": result.value if result.ok else None,
                "error": result.error.message if not result.ok else None,
            },
            status_code=200 if result.ok else 400,
        )

    @server.custom_route("/agentenv/data/delete", methods=["POST"], include_in_schema=False)  # type: ignore[untyped-decorator]
    async def environment_data_delete(request: Request) -> JSONResponse:
        if store is None:
            return JSONResponse({"error": "state-not-derived"}, status_code=503)
        from .writes import delete_entity

        body = await _body(request)
        result = delete_entity(
            store,
            str(body.get("collection") or ""),
            str(body.get("id") or ""),
        )
        return JSONResponse(
            {
                "result": result.value if result.ok else None,
                "error": result.error.message if not result.ok else None,
            },
            status_code=200 if result.ok else 404,
        )

    @server.custom_route("/agentenv/data/document", methods=["POST"], include_in_schema=False)  # type: ignore[untyped-decorator]
    async def environment_data_document(request: Request) -> JSONResponse:
        if store is None:
            return JSONResponse({"error": "state-not-derived"}, status_code=503)
        from .writes import set_document

        body = await _body(request)
        result = set_document(
            store,
            str(body.get("tool") or ""),
            body.get("value"),
            body.get("path") if isinstance(body.get("path"), str) else None,
        )
        return JSONResponse(
            {
                "document": result.value if result.ok else None,
                "error": result.error.message if not result.ok else None,
            },
            status_code=200 if result.ok else 400,
        )

    @server.custom_route("/agentenv/data/add", methods=["POST"], include_in_schema=False)  # type: ignore[untyped-decorator]
    async def environment_data_add(request: Request) -> JSONResponse:
        if store is None:
            return JSONResponse({"error": "state-not-derived"}, status_code=503)
        from .writes import add_entity

        body = await _body(request)
        fields = body.get("fields")
        result = add_entity(
            store,
            str(body.get("type") or ""),
            fields if isinstance(fields, dict) else {},
            collection=body.get("collection"),
        )
        return JSONResponse(
            {
                "entity": result.value if result.ok else None,
                "error": result.error.message if not result.ok else None,
            },
            status_code=200 if result.ok else 400,
        )

    @server.custom_route("/agentenv/data/reset", methods=["POST"], include_in_schema=False)  # type: ignore[untyped-decorator]
    async def environment_data_reset(request: Request) -> JSONResponse:
        del request
        if store is None:
            return JSONResponse({"error": "state-not-derived"}, status_code=503)
        from .writes import reset_state

        return JSONResponse(reset_state(store))

    @server.tool(name="environment_state", description="Current environment state summary.")
    def environment_state() -> dict[str, Any]:
        if store is None:
            return {"available": False, "reason": "state-not-derived"}
        return {"available": True, **environment_coverage(store)}

    @server.tool(name="environment_compare", description="Compare a probe with this replay.")
    def environment_compare(probe_path: str) -> dict[str, Any]:
        import json
        from pathlib import Path

        from .source import RecordedExchange

        payload = json.loads(Path(probe_path).read_text(encoding="utf-8"))
        rows = payload.get("entries") or payload.get("exchanges") or []
        probes = [
            RecordedExchange(
                ordinal=index,
                path=str(item.get("path") or "/"),
                query=item.get("query"),
                status=item.get("status"),
                content_type=item.get("content_type"),
                body_text=item.get("body_text"),
            )
            for index, item in enumerate(rows)
            if isinstance(item, dict)
        ]
        return compare_environment(source, probes)

    return server


def serve_environment(
    source: EnvironmentSource,
    *,
    name: str = "environment",
    host: str = "127.0.0.1",
    port: int = 18765,
    store: EnvironmentStateStore | None = None,
) -> None:
    server = build_environment_server(source, name=name, store=store)
    server.settings.host = host
    server.settings.port = port
    server.run(transport="streamable-http")


__all__ = ["build_environment_server", "serve_environment"]
