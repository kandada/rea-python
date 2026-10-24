"""Confirmed-state write operations for an environment store."""

from __future__ import annotations

from typing import Any

from ...domain.analysis_error import AnalysisInputError
from ...domain.environment_state_rules import scalar_text, segments_of
from ...domain.result import Result, err, ok
from .state_store import EnvironmentStateStore


def _collection_and_id(
    store: EnvironmentStateStore, type_name: str, fields: dict[str, Any]
) -> tuple[str | None, str | None]:
    type_definition = next(
        (item for item in store.types if item.get("collection_template") == type_name), None
    )
    if type_definition is None:
        return None, None
    id_field = str(type_definition.get("id_field") or "id")
    entity_id = scalar_text(fields.get(id_field))
    if entity_id is None:
        return None, None
    pattern = segments_of(str(type_definition.get("collection_template") or ""))
    segments = [
        entity_id if segment.startswith("{") and segment.endswith("}") else segment
        for segment in pattern
    ]
    return "/" + "/".join(segments), entity_id


def add_entity(
    store: EnvironmentStateStore,
    type_name: str,
    fields: dict[str, Any],
    *,
    collection: str | None = None,
) -> Result[dict[str, Any], AnalysisInputError]:
    if not isinstance(fields, dict):
        return err(
            AnalysisInputError(message="fields must be an object", operation="environment-state")
        )
    if collection is None:
        collection, entity_id = _collection_and_id(store, type_name, fields)
    else:
        type_definition = next(
            (item for item in store.types if item.get("collection_template") == type_name), None
        )
        id_field = str((type_definition or {}).get("id_field") or "id")
        entity_id = scalar_text(fields.get(id_field))
    if collection is None or entity_id is None:
        return err(
            AnalysisInputError(
                message="cannot derive collection/id from fields", operation="environment-state"
            )
        )
    entity = {
        "type": type_name,
        "collection": collection,
        "id": entity_id,
        "fields": fields,
        "view_fields": [],
        "record_ordinals": [],
    }
    return store.add(entity)


def merge_entity(
    store: EnvironmentStateStore,
    collection: str,
    entity_id: str,
    fields: dict[str, Any],
) -> Result[dict[str, Any], AnalysisInputError]:
    current = store.get(collection, entity_id)
    if current is None:
        return err(
            AnalysisInputError(message="entity does not exist", operation="environment-state")
        )
    merged = {**current.get("fields", {}), **fields}
    entity = {**current, "fields": merged}
    return store.merge(entity)


def delete_entity(
    store: EnvironmentStateStore, collection: str, entity_id: str
) -> Result[dict[str, Any], AnalysisInputError]:
    deleted = store.delete(collection, entity_id)
    return (
        ok({"deleted": deleted, "collection": collection, "id": entity_id})
        if deleted
        else err(AnalysisInputError(message="entity does not exist", operation="environment-state"))
    )


def set_document(
    store: EnvironmentStateStore, tool: str, value: Any, path: str | None = None
) -> Result[dict[str, Any], AnalysisInputError]:
    initial = store.initial_documents.get(tool)
    if initial is None:
        return err(
            AnalysisInputError(
                message="document view is not in the served state", operation="environment-state"
            )
        )
    return store.set_document({"tool": tool, "path": path or initial.get("path"), "value": value})


def reset_state(store: EnvironmentStateStore) -> dict[str, Any]:
    store.reset()
    return {"reset": True, "digest": store.digest()}


def state_summary(store: EnvironmentStateStore) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for entity in store.entities.values():
        key = str(entity.get("type"))
        counts[key] = counts.get(key, 0) + 1
    return {
        "entity_count": len(store.entities),
        "document_count": len(store.documents),
        "counts": counts,
        "write_clock": store.write_clock,
        "digest": store.digest(),
    }


__all__ = [
    "add_entity",
    "delete_entity",
    "merge_entity",
    "reset_state",
    "set_document",
    "state_summary",
]


def apply_write(
    store: EnvironmentStateStore,
    *,
    method: str,
    path: str,
    args: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
) -> Result[dict[str, Any], AnalysisInputError]:
    """Apply one confirmed write request to the state.

    This is the write-confirmation primitive used by the server when the
    capture's later reads confirmed the effect. It never invents an entity
    whose type/path cannot be derived from the state and the request.
    """
    args = args or {}
    body = body or {}
    from ...domain.environment_state_rules import is_query_post, segments_of

    if is_query_post(method, path):
        return err(
            AnalysisInputError(
                message="query POST does not change state", operation="environment-state"
            )
        )
    type_definition = None
    collection = None
    entity_id = None
    for candidate in store.types:
        template = str(candidate.get("collection_template") or "")
        pattern = segments_of(template)
        concrete = segments_of(path)
        patterns = [pattern]
        if pattern and pattern[-1].startswith("{"):
            patterns.append(pattern[:-1])
        for candidate_pattern in patterns:
            if len(candidate_pattern) != len(concrete):
                continue
            if all(
                segment.startswith("{") or segment == concrete[index]
                for index, segment in enumerate(candidate_pattern)
            ):
                type_definition = candidate
                collection = path
                if (
                    len(candidate_pattern) == len(pattern)
                    and pattern
                    and pattern[-1].startswith("{")
                ):
                    entity_id = concrete[-1] if concrete else None
                break
        if type_definition is not None:
            break
    if type_definition is None:
        return err(
            AnalysisInputError(
                message="no state type matches the write path", operation="environment-state"
            )
        )
    type_name = str(type_definition.get("collection_template"))
    if method == "POST" and entity_id is None:
        result = add_entity(store, type_name, body)
    elif method in ("PUT", "PATCH") and entity_id is not None:
        result = merge_entity(store, collection or path, entity_id, body)
    elif method == "DELETE" and entity_id is not None:
        result = delete_entity(store, collection or path, entity_id)
    else:
        return err(
            AnalysisInputError(
                message="write method/path combination is not supported",
                operation="environment-state",
            )
        )
    return ok(
        {
            "applied": result.ok,
            "method": method,
            "path": path,
            "type": type_name,
            "entity_id": entity_id,
            "result": result.value if result.ok else None,
            "error": result.error.message if not result.ok else None,
        }
    )
