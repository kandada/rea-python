"""Validation and retention rules for ``rea-state/v1`` environment documents."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ...domain.analysis_error import AnalysisInputError
from ...domain.environment_state_rules import (
    canonical_json,
    has_prototype_key,
    is_param,
    normalized_path,
    same,
    scalar_text,
    segments_of,
)
from ...domain.result import Result, err, ok

STATE_INTAKE_LIMIT_BYTES = 32 * 1024 * 1024
REA_STATE_FORMAT = "rea-state/v1"
ENVIRONMENT_OPERATION = "environment-serve"


@dataclass
class EnvironmentState:
    evidence_id: str
    types: list[dict[str, Any]] = field(default_factory=list)
    views: dict[str, dict[str, Any]] = field(default_factory=dict)
    entities: list[dict[str, Any]] = field(default_factory=list)
    documents: list[dict[str, Any]] = field(default_factory=list)
    writes: dict[str, dict[str, Any]] = field(default_factory=dict)
    write_clock: str | None = None


@dataclass
class StateContent:
    entities: list[dict[str, Any]]
    documents: list[dict[str, Any]]


def _issue(path: list[Any], message: str) -> dict[str, Any]:
    return {"path": path, "reason": "invalid_value", "message": message}


def _error(issue: dict[str, Any], message: str) -> AnalysisInputError:
    return AnalysisInputError(
        message=message,
        operation=ENVIRONMENT_OPERATION,
        details={"issues": [issue]},
    )


def _exact_json(value: Any) -> bool:
    if isinstance(value, float):
        return value == value and value not in (float("inf"), float("-inf"))
    if isinstance(value, list):
        return all(_exact_json(item) for item in value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and _exact_json(item) for key, item in value.items())
    return value is None or isinstance(value, (str, int, bool))


def is_loadable_value(value: Any) -> bool:
    return _exact_json(value) and not has_prototype_key(value)


def unloadable_member(object_value: dict[str, Any]) -> str | None:
    for key, value in object_value.items():
        if key == "__proto__" or not is_loadable_value(value):
            return key
    return None


def _instantiates(collection: str, template: str) -> bool:
    concrete = segments_of(collection)
    pattern = segments_of(template)
    return (
        normalized_path(collection) == collection
        and len(concrete) == len(pattern)
        and all(
            is_param(segment) or segment == concrete[index] for index, segment in enumerate(pattern)
        )
    )


def _entity_key(entity: dict[str, Any]) -> tuple[Any, Any, Any]:
    return entity.get("type"), entity.get("collection"), entity.get("id")


def _view_problem(
    state: EnvironmentState,
    type_definition: dict[str, Any],
    entity: dict[str, Any],
    path: list[Any],
) -> dict[str, Any] | None:
    tools: set[str] = set()
    for index, view_fields in enumerate(entity.get("view_fields") or []):
        tool = view_fields.get("tool")
        view = state.views.get(str(tool))
        if (
            view is None
            or view.get("shape") not in ("item", "list")
            or view.get("type") != entity.get("type")
            or tool in tools
        ):
            return _issue(
                [*path, "view_fields", index, "tool"],
                "is not an item or list view of the entity's type, or repeats one",
            )
        tools.add(str(tool))
        fields = view_fields.get("fields") or {}
        id_field = str(type_definition.get("id_field") or "id")
        if id_field in fields and scalar_text(fields.get(id_field)) != entity.get("id"):
            return _issue(
                [*path, "view_fields", index, "fields"],
                f"sets the type's {id_field} field to a value other than the entity's id",
            )
    return None


def _entity_problem(
    state: EnvironmentState,
    initial: dict[tuple[Any, Any, Any], dict[str, Any]],
    seen: set[tuple[Any, Any, Any]],
    entity: dict[str, Any],
    path: list[Any],
) -> dict[str, Any] | None:
    type_definition = next(
        (item for item in state.types if item.get("collection_template") == entity.get("type")),
        None,
    )
    if type_definition is None:
        return _issue([*path, "type"], "is not a type of the served state")
    if not _instantiates(
        str(entity.get("collection") or ""), str(type_definition.get("collection_template") or "")
    ):
        return _issue(
            [*path, "collection"],
            f"does not match its type's collection_template {type_definition.get('collection_template')}",
        )
    id_field = str(type_definition.get("id_field") or "id")
    if scalar_text((entity.get("fields") or {}).get(id_field)) != entity.get("id"):
        return _issue([*path, "id"], f"does not equal the entity's {id_field} field")
    key = _entity_key(entity)
    if key in seen:
        return _issue([*path, "id"], "repeats an earlier entity's key")
    seen.add(key)
    ordinals = entity.get("record_ordinals") or []
    if ordinals and not same(ordinals, initial.get(key, {}).get("record_ordinals", [])):
        return _issue(
            [*path, "record_ordinals"],
            "cites records the served Evidence does not cite for this entity",
        )
    return _view_problem(state, type_definition, entity, path)


def _documents_problem(
    state: EnvironmentState, documents: list[dict[str, Any]]
) -> dict[str, Any] | None:
    tools: set[str] = set()
    for index, document in enumerate(documents):
        initial = next(
            (item for item in state.documents if item.get("tool") == document.get("tool")), None
        )
        if (
            state.views.get(str(document.get("tool"))) is None
            or state.views[str(document.get("tool"))].get("shape") != "document"
            or initial is None
            or document.get("tool") in tools
        ):
            return _issue(
                ["rea_state", "documents", index, "tool"],
                "is not a document view of the served state, or repeats one",
            )
        tools.add(str(document.get("tool")))
        if document.get("path") != initial.get("path"):
            return _issue(
                ["rea_state", "documents", index, "path"],
                f"differs from the initial document's path {initial.get('path')}",
            )
        if document.get("record_ordinal") is not None and document.get(
            "record_ordinal"
        ) != initial.get("record_ordinal"):
            return _issue(
                ["rea_state", "documents", index, "record_ordinal"],
                f"is not the initial document's record {initial.get('record_ordinal')}",
            )
    return None


def parse_state_document(
    state: EnvironmentState, value: Any, owned: bool = False
) -> Result[StateContent, AnalysisInputError]:
    del owned
    if not isinstance(value, dict) or not isinstance(value.get("rea_state"), dict):
        return err(
            _error(
                _issue([], "is not a rea-state/v1 document"),
                "The document is not a valid rea-state/v1 state.",
            )
        )
    document = value["rea_state"]
    allowed = {"version", "state_evidence_id", "types", "entities", "documents"}
    extra = next((key for key in document if key not in allowed), None)
    if extra is not None:
        return err(
            _error(
                _issue(["rea_state", extra], f"has a member {REA_STATE_FORMAT} does not define"),
                "The document is not a valid rea-state/v1 state.",
            )
        )
    if document.get("version") != 1:
        return err(
            _error(
                _issue(["rea_state", "version"], "is not version 1"),
                "The document is not a valid rea-state/v1 state.",
            )
        )
    if has_prototype_key(document):
        return err(
            _error(
                _issue(["rea_state"], "contains a __proto__ member"),
                "The document is not a valid rea-state/v1 state.",
            )
        )
    entities = document.get("entities")
    documents = document.get("documents")
    if not isinstance(entities, list) or not isinstance(documents, list):
        return err(
            _error(
                _issue(["rea_state"], "entities and documents must be arrays"),
                "The document is not a valid rea-state/v1 state.",
            )
        )
    if (
        document.get("state_evidence_id") is not None
        and document.get("state_evidence_id") != state.evidence_id
    ):
        return err(
            _error(
                _issue(
                    ["rea_state", "state_evidence_id"],
                    f"is not the served state's Evidence {state.evidence_id}",
                ),
                "The document is not a valid rea-state/v1 state.",
            )
        )
    if document.get("types") is not None and canonical_json(document["types"]) != canonical_json(
        state.types
    ):
        return err(
            _error(
                _issue(["rea_state", "types"], "differs from the served types"),
                "The document is not a valid rea-state/v1 state.",
            )
        )
    initial = {_entity_key(entity): entity for entity in state.entities}
    seen: set[tuple[Any, Any, Any]] = set()
    for index, entity in enumerate(entities):
        if not isinstance(entity, dict):
            return err(
                _error(
                    _issue(["rea_state", "entities", index], "is not an object"),
                    "The document is not a valid rea-state/v1 state.",
                )
            )
        missing = next(
            (key for key in ("type", "collection", "id", "fields") if key not in entity), None
        )
        if missing is not None:
            return err(
                _error(
                    _issue(["rea_state", "entities", index, missing], "is required"),
                    "The document is not a valid rea-state/v1 state.",
                )
            )
        if not isinstance(entity["fields"], dict) or not is_loadable_value(entity["fields"]):
            return err(
                _error(
                    _issue(
                        ["rea_state", "entities", index, "fields"],
                        "holds a value that is not exactly representable JSON",
                    ),
                    "The document is not a valid rea-state/v1 state.",
                )
            )
        problem = _entity_problem(state, initial, seen, entity, ["rea_state", "entities", index])
        if problem is not None:
            return err(_error(problem, "The document is not a valid rea-state/v1 state."))
    documents_problem = _documents_problem(state, documents)
    if documents_problem is not None:
        return err(_error(documents_problem, "The document is not a valid rea-state/v1 state."))
    held_entities = []
    for entity in entities:
        recorded = initial.get(_entity_key(entity))
        unchanged = (
            recorded is not None
            and same(entity.get("fields"), recorded.get("fields"))
            and same(entity.get("view_fields") or [], recorded.get("view_fields") or [])
        )
        held_entities.append(
            {
                "type": entity.get("type"),
                "collection": entity.get("collection"),
                "id": entity.get("id"),
                "fields": entity.get("fields"),
                "view_fields": entity.get("view_fields") or [],
                "record_ordinals": (
                    list(recorded.get("record_ordinals") or [])
                    if unchanged and recorded is not None
                    else []
                ),
            }
        )
    held_documents = []
    for document in documents:
        recorded = next(
            (item for item in state.documents if item.get("tool") == document.get("tool")), None
        )
        held_documents.append(
            {
                "tool": document.get("tool"),
                "path": document.get("path"),
                "value": document.get("value"),
                **(
                    {"record_ordinal": recorded.get("record_ordinal")}
                    if recorded is not None and same(document.get("value"), recorded.get("value"))
                    else {}
                ),
            }
        )
    return ok(StateContent(entities=held_entities, documents=held_documents))


__all__ = [
    "ENVIRONMENT_OPERATION",
    "STATE_INTAKE_LIMIT_BYTES",
    "EnvironmentState",
    "StateContent",
    "is_loadable_value",
    "parse_state_document",
    "unloadable_member",
]
