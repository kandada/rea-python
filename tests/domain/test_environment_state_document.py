from __future__ import annotations

from rea_mcp.application.environment.state_document import (
    EnvironmentState,
    parse_state_document,
    unloadable_member,
)


def _state() -> EnvironmentState:
    return EnvironmentState(
        evidence_id="ev_state",
        types=[
            {
                "collection_template": "/api/items/{id}",
                "id_field": "id",
                "id_basis": "path-parameter",
                "init_before_ordinal": None,
                "volatile_fields": [],
            }
        ],
        views={
            "get_item": {"shape": "item", "type": "/api/items/{id}", "tool": "get_item"},
            "list_items": {"shape": "list", "type": "/api/items/{id}", "tool": "list_items"},
            "get_doc": {"shape": "document", "tool": "get_doc"},
        },
        entities=[
            {
                "type": "/api/items/{id}",
                "collection": "/api/items/1",
                "id": "1",
                "fields": {"id": "1", "name": "one"},
                "view_fields": [{"tool": "get_item", "fields": {"id": "1", "name": "one"}}],
                "record_ordinals": [0],
            }
        ],
        documents=[{"tool": "get_doc", "path": "/config", "value": {"a": 1}, "record_ordinal": 1}],
    )


def _valid_document() -> dict:
    return {
        "rea_state": {
            "version": 1,
            "state_evidence_id": "ev_state",
            "entities": [
                {
                    "type": "/api/items/{id}",
                    "collection": "/api/items/1",
                    "id": "1",
                    "fields": {"id": "1", "name": "one"},
                    "view_fields": [{"tool": "get_item", "fields": {"id": "1", "name": "one"}}],
                    "record_ordinals": [0],
                }
            ],
            "documents": [{"tool": "get_doc", "path": "/config", "value": {"a": 1}}],
        }
    }


def test_valid_document_retains_evidence_ordinals() -> None:
    result = parse_state_document(_state(), _valid_document())
    assert result.ok
    assert result.value.entities[0]["record_ordinals"] == [0]
    assert result.value.documents[0]["record_ordinal"] == 1


def test_edited_value_drops_record_ordinal() -> None:
    document = _valid_document()
    document["rea_state"]["entities"][0]["fields"]["name"] = "changed"
    result = parse_state_document(_state(), document)
    assert result.ok
    assert result.value.entities[0]["record_ordinals"] == []


def test_invalid_identity_and_collection_are_refused() -> None:
    document = _valid_document()
    document["rea_state"]["entities"][0]["id"] = "2"
    assert not parse_state_document(_state(), document).ok
    document = _valid_document()
    document["rea_state"]["entities"][0]["collection"] = "/api/other/1"
    assert not parse_state_document(_state(), document).ok


def test_duplicate_entity_and_bad_document_path_are_refused() -> None:
    document = _valid_document()
    document["rea_state"]["entities"].append(dict(document["rea_state"]["entities"][0]))
    assert not parse_state_document(_state(), document).ok
    document = _valid_document()
    document["rea_state"]["documents"][0]["path"] = "/other"
    assert not parse_state_document(_state(), document).ok


def test_prototype_member_is_refused() -> None:
    document = _valid_document()
    document["rea_state"]["entities"][0]["fields"]["__proto__"] = {"polluted": True}
    result = parse_state_document(_state(), document)
    assert not result.ok
    assert unloadable_member({"__proto__": 1}) == "__proto__"
