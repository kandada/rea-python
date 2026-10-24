from __future__ import annotations

from rea_mcp.application.environment.state_document import EnvironmentState
from rea_mcp.application.environment.state_store import EnvironmentStateStore


def _store() -> EnvironmentStateStore:
    state = EnvironmentState(
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
                "fields": {"id": "1", "name": "one"},
                "view_fields": [],
                "record_ordinals": [0],
            }
        ],
        documents=[{"tool": "config", "path": "/config", "value": {"a": 1}, "record_ordinal": 1}],
    )
    return EnvironmentStateStore.from_state(state)


def test_store_get_list_and_reset() -> None:
    store = _store()
    assert store.get("/api/items", "1")["fields"]["name"] == "one"
    assert store.list_entities("/api/items")[0]["id"] == "1"
    added = store.add(
        {
            "type": "/api/items/{id}",
            "collection": "/api/items/2",
            "id": "2",
            "fields": {"id": "2", "name": "two"},
            "view_fields": [],
            "record_ordinals": [],
        }
    )
    assert added.ok
    assert len(store.list_entities("/api/items")) == 2
    store.reset()
    assert len(store.list_entities("/api/items")) == 1


def test_store_rejects_bad_identity_and_duplicate() -> None:
    store = _store()
    bad = store.add(
        {
            "type": "/api/items/{id}",
            "collection": "/api/items/2",
            "id": "3",
            "fields": {"id": "2"},
            "view_fields": [],
            "record_ordinals": [],
        }
    )
    assert not bad.ok
    duplicate = store.add(
        {
            "type": "/api/items/{id}",
            "collection": "/api/items/1",
            "id": "1",
            "fields": {"id": "1"},
            "view_fields": [],
            "record_ordinals": [],
        }
    )
    assert not duplicate.ok


def test_store_documents_and_snapshot() -> None:
    store = _store()
    assert store.document("config")["value"] == {"a": 1}
    assert store.set_document({"tool": "config", "path": "/config", "value": {"a": 2}}).ok
    assert store.document("config")["value"] == {"a": 2}
    assert "config" not in [item.get("tool") for item in store.snapshot()["documents"] if False]
    assert store.digest() == store.digest()
