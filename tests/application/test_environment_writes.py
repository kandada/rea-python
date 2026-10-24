from __future__ import annotations

from rea_mcp.application.environment.state_document import EnvironmentState
from rea_mcp.application.environment.state_store import EnvironmentStateStore
from rea_mcp.application.environment.writes import (
    add_entity,
    delete_entity,
    merge_entity,
    reset_state,
    set_document,
    state_summary,
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
                    "fields": {"id": "1", "name": "one"},
                    "view_fields": [],
                    "record_ordinals": [0],
                }
            ],
            documents=[
                {"tool": "config", "path": "/config", "value": {"a": 1}, "record_ordinal": 1}
            ],
        )
    )


def test_add_merge_delete_and_summary() -> None:
    store = _store()
    added = add_entity(store, "/api/items/{id}", {"id": "2", "name": "two"})
    assert added.ok
    assert state_summary(store)["entity_count"] == 2
    merged = merge_entity(store, "/api/items/1", "1", {"name": "uno"})
    assert merged.ok
    assert store.get("/api/items/1", "1")["fields"]["name"] == "uno"
    assert delete_entity(store, "/api/items", "2").ok
    assert state_summary(store)["entity_count"] == 1


def test_document_reset_and_errors() -> None:
    store = _store()
    assert set_document(store, "config", {"a": 2}).ok
    assert store.document("config")["value"] == {"a": 2}
    reset_state(store)
    assert store.document("config")["value"] == {"a": 1}
    assert not delete_entity(store, "/api/items/1", "missing").ok
    assert not set_document(store, "missing", {}).ok


def test_apply_write_create_merge_delete() -> None:
    from rea_mcp.application.environment.writes import apply_write

    store = _store()
    created = apply_write(store, method="POST", path="/api/items", body={"id": "2", "name": "two"})
    assert created.ok and created.value["applied"]
    assert store.get("/api/items/2", "2") is not None
    merged = apply_write(store, method="PATCH", path="/api/items/2", body={"name": "dos"})
    assert merged.ok and merged.value["applied"]
    assert store.get("/api/items/2", "2")["fields"]["name"] == "dos"
    deleted = apply_write(store, method="DELETE", path="/api/items/2")
    assert deleted.ok and deleted.value["applied"]
    assert store.get("/api/items/2", "2") is None
