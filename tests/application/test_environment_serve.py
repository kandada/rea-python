from __future__ import annotations

import asyncio
import json

from rea_mcp.application.environment.coverage import environment_coverage
from rea_mcp.application.environment.serve import build_environment_server
from rea_mcp.application.environment.source import EnvironmentSource, RecordedExchange
from rea_mcp.application.environment.state_document import EnvironmentState
from rea_mcp.application.environment.state_store import EnvironmentStateStore


def _source() -> EnvironmentSource:
    return EnvironmentSource(
        manifest={
            "name": "demo",
            "tools": [
                {
                    "name": "get_item",
                    "method": "GET",
                    "path_template": "/api/items/{p1}",
                    "parameters": {"p1": "path"},
                }
            ],
        },
        manifest_evidence_id="ev_m",
        evidence_id="ev_c",
        capture_kind="web-network-capture",
        capture_sha256=None,
        exchanges={0: RecordedExchange(0, "/api/items/1", None, 200, "text/plain", "ok")},
    )


def _store() -> EnvironmentStateStore:
    return EnvironmentStateStore.from_state(
        EnvironmentState(
            evidence_id="ev",
            types=[
                {
                    "collection_template": "/api/items/{id}",
                    "id_field": "id",
                    "id_basis": "path-parameter",
                    "init_before_ordinal": None,
                    "volatile_fields": [],
                }
            ],
            views={},
            entities=[
                {
                    "type": "/api/items/{id}",
                    "collection": "/api/items/1",
                    "id": "1",
                    "fields": {"id": "1"},
                    "view_fields": [],
                    "record_ordinals": [0],
                }
            ],
            documents=[],
        )
    )


def test_environment_coverage() -> None:
    coverage = environment_coverage(_store())
    assert coverage["entity_count"] == 1
    assert coverage["coverage"]["state"] == "complete"


def test_environment_server_exposes_manifest_and_state_tools() -> None:
    server = build_environment_server(_source(), name="demo", store=_store())

    async def run() -> None:
        names = {tool.name for tool in await server.list_tools()}
        assert {"get_item", "environment_state", "environment_compare"} <= names
        result = await server.call_tool("get_item", {"p1": "1"})
        if isinstance(result, tuple):
            result = result[1] if isinstance(result[1], dict) else result[0]
        if not isinstance(result, dict):
            result = json.loads(
                next(block.text for block in result if getattr(block, "text", None))
            )
        assert result["ok"] is True
        assert result["status"] == 200

    asyncio.run(run())


def test_environment_data_routes() -> None:
    from starlette.testclient import TestClient

    app = build_environment_server(_source(), name="demo", store=_store()).streamable_http_app()
    with TestClient(app) as client:
        listed = client.post("/agentenv/data/list", json={"collection": "/api/items/1"})
        assert listed.status_code == 200
        assert listed.json()["count"] == 1
        merged = client.post(
            "/agentenv/data/merge",
            json={"collection": "/api/items/1", "id": "1", "fields": {"name": "x"}},
        )
        assert merged.status_code == 200
        assert merged.json()["entity"]["fields"]["name"] == "x"
        deleted = client.post(
            "/agentenv/data/delete", json={"collection": "/api/items/1", "id": "1"}
        )
        assert deleted.status_code == 200
        missing = client.post(
            "/agentenv/data/delete", json={"collection": "/api/items/1", "id": "1"}
        )
        assert missing.status_code == 404


def test_environment_data_routes_without_store_return_503() -> None:
    from starlette.testclient import TestClient

    app = build_environment_server(_source(), name="demo", store=None).streamable_http_app()
    with TestClient(app) as client:
        for path in (
            "/agentenv/data/get",
            "/agentenv/data/list",
            "/agentenv/data/merge",
            "/agentenv/data/delete",
            "/agentenv/data/document",
            "/agentenv/data/add",
            "/agentenv/data/reset",
        ):
            response = client.post(path, json={})
            assert response.status_code == 503, path
            assert response.json()["error"] == "state-not-derived"


def test_environment_data_get_add_and_reset() -> None:
    from starlette.testclient import TestClient

    store = _store()
    app = build_environment_server(_source(), name="demo", store=store).streamable_http_app()
    with TestClient(app) as client:
        found = client.post("/agentenv/data/get", json={"collection": "/api/items/1", "id": "1"})
        assert found.status_code == 200
        assert found.json()["entity"]["id"] == "1"
        missing = client.post("/agentenv/data/get", json={"collection": "/api/items/1", "id": "9"})
        assert missing.status_code == 404
        added = client.post(
            "/agentenv/data/add",
            json={
                "type": "/api/items/{id}",
                "fields": {"id": "2", "name": "two"},
            },
        )
        assert added.status_code == 200
        assert added.json()["entity"]["id"] == "2"
        duplicate = client.post(
            "/agentenv/data/add",
            json={"type": "/api/items/{id}", "fields": {"id": "2"}},
        )
        assert duplicate.status_code == 400
        reset = client.post("/agentenv/data/reset")
        assert reset.status_code == 200
        assert reset.json()["reset"] is True
        assert store.get("/api/items/1", "2") is None


def test_environment_document_route_and_card() -> None:
    from starlette.testclient import TestClient

    from rea_mcp.application.environment.state_document import EnvironmentState

    state = EnvironmentState(
        evidence_id="ev",
        types=[],
        views={"config": {"shape": "document", "tool": "config"}},
        entities=[],
        documents=[{"tool": "config", "path": "/config", "value": {"a": 1}}],
    )
    store = EnvironmentStateStore.from_state(state)
    app = build_environment_server(_source(), name="demo", store=store).streamable_http_app()
    with TestClient(app) as client:
        updated = client.post("/agentenv/data/document", json={"tool": "config", "value": {"a": 2}})
        assert updated.status_code == 200
        assert updated.json()["document"]["value"] == {"a": 2}
        rejected = client.post("/agentenv/data/document", json={"tool": "missing", "value": {}})
        assert rejected.status_code == 400
        card = client.get("/.well-known/agent-env.json")
        assert card.status_code == 200
        assert card.json()["name"] == "demo"
        assert card.json()["state"] is True


def test_environment_compare_tool(tmp_path) -> None:
    probe = tmp_path / "probe.json"
    probe.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "path": "/api/items/1",
                        "status": 200,
                        "content_type": "text/plain",
                        "body_text": "ok",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    server = build_environment_server(_source(), name="demo", store=_store())

    async def run() -> None:
        result = await server.call_tool("environment_compare", {"probe_path": str(probe)})
        if isinstance(result, tuple):
            result = result[1] if isinstance(result[1], dict) else result[0]
        if not isinstance(result, dict):
            result = json.loads(
                next(block.text for block in result if getattr(block, "text", None))
            )
        assert result["probe_count"] == 1
        assert result["status"] in ("changed", "unchanged")

    asyncio.run(run())
