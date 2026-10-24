from __future__ import annotations

from rea_mcp.application.environment.extract import extract_state
from rea_mcp.application.environment.source import EnvironmentSource, RecordedExchange


def _source() -> EnvironmentSource:
    return EnvironmentSource(
        manifest={
            "tools": [
                {
                    "name": "get_item",
                    "method": "GET",
                    "path_template": "/api/items/{id}",
                    "parameters": {"id": "path"},
                    "record_ordinals": [0],
                },
                {
                    "name": "list_items",
                    "method": "GET",
                    "path_template": "/api/items",
                    "parameters": {},
                    "record_ordinals": [1],
                },
                {
                    "name": "config",
                    "method": "GET",
                    "path_template": "/config",
                    "parameters": {},
                    "record_ordinals": [2],
                },
            ]
        },
        manifest_evidence_id="ev_m",
        evidence_id="ev_c",
        capture_kind="web-network-capture",
        capture_sha256=None,
        exchanges={
            0: RecordedExchange(
                0, "/api/items/1", None, 200, "application/json", '{"id":"1","name":"one"}'
            ),
            1: RecordedExchange(
                1, "/api/items", None, 200, "application/json", '{"data":[{"id":"2","name":"two"}]}'
            ),
            2: RecordedExchange(2, "/config", None, 200, "application/json", '{"mode":"test"}'),
        },
    )


def test_extract_item_list_and_document() -> None:
    result = extract_state(_source())
    state = result.state
    assert result.coverage["entities"] >= 2
    assert any(item["id"] == "1" for item in state.entities)
    assert any(item["id"] == "2" for item in state.entities)
    assert state.documents[0]["tool"] == "config"
    assert state.views["get_item"]["shape"] == "item"
    assert state.views["list_items"]["shape"] == "list"


def test_extract_merges_repeated_entity_observations() -> None:
    from rea_mcp.application.environment.source import EnvironmentSource, RecordedExchange

    source = EnvironmentSource(
        manifest={
            "name": "demo",
            "tools": [
                {
                    "name": "get_item",
                    "method": "GET",
                    "path_template": "/api/items/{id}",
                    "record_ordinals": [0, 1],
                }
            ],
        },
        manifest_evidence_id="ev_m",
        evidence_id="ev_c",
        capture_kind="environment-capture",
        capture_sha256=None,
        exchanges={
            0: RecordedExchange(
                0,
                "/api/items/1",
                None,
                200,
                "application/json",
                '{"id":"1","name":"a","updatedAt":"x"}',
            ),
            1: RecordedExchange(
                1,
                "/api/items/1",
                None,
                200,
                "application/json",
                '{"id":"1","name":"a","updatedAt":"y"}',
            ),
        },
    )
    result = extract_state(source)
    assert len(result.state.entities) == 1
    entity = result.state.entities[0]
    assert entity["record_ordinals"] == [0, 1]
    assert len(entity["view_fields"]) == 2
    assert result.state.types[0]["volatile_fields"] == ["updatedAt"]
