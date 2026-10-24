"""Heuristic state extraction from a validated environment capture."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ...domain.environment_state_rules import (
    canonical_json,
    collection_path_of,
    identity_candidates,
    last_segment_value,
    list_items,
    locate_item,
    locate_list,
    normalized_path,
    pointer_to,
    scalar_text,
)
from .source import EnvironmentSource, RecordedExchange, replayed_body


@dataclass
class ExtractionResult:
    state: Any
    coverage: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)


def _body(exchange: RecordedExchange) -> Any:
    body = replayed_body(exchange)
    return body.get("value") if body.get("kind") == "json" else None


def _locate_list_deep(body: Any, depth: int = 0) -> str | None:
    pointer = locate_list(body, None)
    if pointer is not None:
        return pointer
    if not isinstance(body, dict) or depth >= 6:
        return None
    fallback = None
    for key, value in body.items():
        if isinstance(value, dict):
            nested = _locate_list_deep(value, depth + 1)
            if nested is not None:
                candidate = pointer_to(str(key)) + nested
                items = list_items(body, candidate) or []
                if identity_candidates(items):
                    return candidate
                fallback = fallback or candidate
        elif isinstance(value, list) and value and all(isinstance(item, dict) for item in value):
            candidate = pointer_to(str(key))
            if identity_candidates(value):
                return candidate
            fallback = fallback or candidate
    return fallback


def _item_type(template: str) -> str:
    return template


def extract_state(source: EnvironmentSource) -> ExtractionResult:
    from .state_document import EnvironmentState

    types: dict[str, dict[str, Any]] = {}
    views: dict[str, dict[str, Any]] = {}
    entities: dict[tuple[str, str, str], dict[str, Any]] = {}
    documents: list[dict[str, Any]] = []
    limitations: list[str] = []
    for tool in source.manifest.get("tools") or []:
        name = str(tool.get("name") or "")
        method = str(tool.get("method") or "GET")
        template = str(tool.get("path_template") or "/")
        if method != "GET":
            continue
        for ordinal in tool.get("record_ordinals") or []:
            exchange = source.exchanges.get(int(ordinal))
            if exchange is None:
                continue
            body = _body(exchange)
            if body is None:
                continue
            located = locate_item(body, last_segment_value(exchange.path))
            if located is not None and "{" in template:
                item = _at_pointer(body, located["pointer"])
                if not isinstance(item, dict):
                    continue
                entity_id = last_segment_value(exchange.path)
                id_field = located["keys"][0]
                type_name = _item_type(template)
                types.setdefault(
                    type_name,
                    {
                        "collection_template": template,
                        "id_field": id_field,
                        "id_basis": "path-parameter",
                        "init_before_ordinal": None,
                        "volatile_fields": [],
                    },
                )
                collection = collection_path_of({"path": exchange.path}, True)
                key = (type_name, collection, entity_id)
                _merge_entity(
                    entities,
                    key,
                    type_name,
                    collection,
                    entity_id,
                    item,
                    name,
                    exchange.ordinal,
                )
                views.setdefault(
                    name,
                    {
                        "tool": name,
                        "shape": "item",
                        "type": type_name,
                        "fields": list(item),
                        "required_fields": list(item),
                        "checked_record_ordinals": [],
                    },
                )
                views[name]["checked_record_ordinals"].append(exchange.ordinal)
                continue
            pointer = _locate_list_deep(body)
            if pointer is None:
                if isinstance(body, dict):
                    documents.append(
                        {
                            "tool": name,
                            "path": exchange.path,
                            "value": body,
                            "record_ordinal": exchange.ordinal,
                        }
                    )
                    views.setdefault(
                        name, {"tool": name, "shape": "document", "checked_record_ordinals": []}
                    )
                    views[name]["checked_record_ordinals"].append(exchange.ordinal)
                continue
            items = list_items(body, pointer)
            if not items:
                continue
            candidates = identity_candidates(items)
            if not candidates:
                limitations.append(f"{name}: list items have no identity field")
                continue
            id_field = candidates[0]
            type_name = normalized_path(template).rstrip("/") + "/{id}"
            types.setdefault(
                type_name,
                {
                    "collection_template": type_name,
                    "id_field": id_field,
                    "id_basis": "field-name",
                    "init_before_ordinal": None,
                    "volatile_fields": [],
                },
            )
            collection = normalized_path(template)
            for item in items:
                list_id = scalar_text(item.get(id_field))
                if list_id is None:
                    continue
                _merge_entity(
                    entities,
                    (type_name, collection, list_id),
                    type_name,
                    collection,
                    list_id,
                    item,
                    name,
                    exchange.ordinal,
                )
            fields = list(items[0])
            views.setdefault(
                name,
                {
                    "tool": name,
                    "shape": "list",
                    "type": type_name,
                    "fields": fields,
                    "required_fields": fields,
                    "checked_record_ordinals": [],
                    "membership": "all",
                },
            )
            views[name]["checked_record_ordinals"].append(exchange.ordinal)
    for entity in entities.values():
        type_definition = types.get(str(entity["type"]))
        if type_definition is None:
            continue
        volatile: list[str] = []
        for field_name in entity["fields"]:
            values = {
                canonical_json(view["fields"][field_name])
                for view in entity["view_fields"]
                if field_name in view["fields"]
            }
            if len(values) > 1:
                volatile.append(field_name)
        type_definition["volatile_fields"] = sorted(
            set(type_definition["volatile_fields"]) | set(volatile)
        )
    state = EnvironmentState(
        evidence_id=source.evidence_id,
        types=list(types.values()),
        views=views,
        entities=list(entities.values()),
        documents=documents,
    )
    return ExtractionResult(
        state=state,
        coverage={
            "types": len(types),
            "entities": len(entities),
            "documents": len(documents),
            "views": len(views),
        },
        limitations=limitations,
    )


def _merge_entity(
    entities: dict[tuple[str, str, str], dict[str, Any]],
    key: tuple[str, str, str],
    type_name: str,
    collection: str,
    entity_id: str,
    item: dict[str, Any],
    tool: str,
    ordinal: int,
) -> None:
    existing = entities.get(key)
    if existing is None:
        entities[key] = {
            "type": type_name,
            "collection": collection,
            "id": entity_id,
            "fields": dict(item),
            "view_fields": [{"tool": tool, "fields": dict(item)}],
            "record_ordinals": [ordinal],
        }
        return
    existing["fields"].update(item)
    existing["view_fields"].append({"tool": tool, "fields": dict(item)})
    if ordinal not in existing["record_ordinals"]:
        existing["record_ordinals"].append(ordinal)


def _at_pointer(body: Any, pointer: str) -> Any:
    from ...domain.environment_state_rules import at

    return at(body, pointer)


__all__ = ["ExtractionResult", "extract_state"]
