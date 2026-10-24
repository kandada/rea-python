"""In-memory environment state store (read/write/add/reset)."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

from ...domain.analysis_error import AnalysisInputError
from ...domain.environment_state_rules import (
    canonical_json,
    normalized_path,
    scalar_text,
    segments_of,
)
from ...domain.result import Result, err, ok


@dataclass
class EnvironmentStateStore:
    evidence_id: str
    types: list[dict[str, Any]]
    views: dict[str, dict[str, Any]]
    entities: dict[tuple[Any, Any, Any], dict[str, Any]] = field(default_factory=dict)
    documents: dict[str, dict[str, Any]] = field(default_factory=dict)
    write_clock: str | None = None
    initial_entities: dict[tuple[Any, Any, Any], dict[str, Any]] = field(default_factory=dict)
    initial_documents: dict[str, dict[str, Any]] = field(default_factory=dict)

    @classmethod
    def from_state(cls, state: Any) -> EnvironmentStateStore:
        store = cls(
            evidence_id=state.evidence_id,
            types=copy.deepcopy(state.types),
            views=copy.deepcopy(state.views),
            write_clock=getattr(state, "write_clock", None),
        )
        for entity in state.entities:
            store.entities[store._key(entity)] = copy.deepcopy(entity)
        for document in state.documents:
            store.documents[str(document.get("tool"))] = copy.deepcopy(document)
        store.initial_entities = copy.deepcopy(store.entities)
        store.initial_documents = copy.deepcopy(store.documents)
        return store

    def _key(self, entity: dict[str, Any]) -> tuple[Any, Any, Any]:
        return entity.get("type"), entity.get("collection"), entity.get("id")

    def _type(self, name: str) -> dict[str, Any] | None:
        return next((item for item in self.types if item.get("collection_template") == name), None)

    def _validate(self, entity: dict[str, Any]) -> AnalysisInputError | None:
        type_definition = self._type(str(entity.get("type") or ""))
        if type_definition is None:
            return AnalysisInputError(
                message=f"unknown environment type: {entity.get('type')}",
                operation="environment-state",
            )
        collection = str(entity.get("collection") or "")
        template = str(type_definition.get("collection_template") or "")
        concrete = segments_of(collection)
        pattern = segments_of(template)
        if len(concrete) != len(pattern) or any(
            not (segment.startswith("{") and segment.endswith("}")) and segment != concrete[index]
            for index, segment in enumerate(pattern)
        ):
            return AnalysisInputError(
                message=f"collection {collection} does not match {template}",
                operation="environment-state",
            )
        id_field = str(type_definition.get("id_field") or "id")
        if scalar_text((entity.get("fields") or {}).get(id_field)) != entity.get("id"):
            return AnalysisInputError(
                message=f"entity id does not match its {id_field} field",
                operation="environment-state",
            )
        return None

    @staticmethod
    def _in_collection(entity: dict[str, Any], collection: str) -> bool:
        value = normalized_path(str(entity.get("collection")))
        return value == collection or value.startswith(collection + "/")

    def get(self, collection: str, entity_id: str) -> dict[str, Any] | None:
        normalized = normalized_path(collection)
        return next(
            (
                copy.deepcopy(entity)
                for entity in self.entities.values()
                if self._in_collection(entity, normalized)
                and str(entity.get("id")) == str(entity_id)
            ),
            None,
        )

    def list_entities(self, collection: str) -> list[dict[str, Any]]:
        normalized = normalized_path(collection)
        return [
            copy.deepcopy(entity)
            for entity in sorted(self.entities.values(), key=lambda item: str(item.get("id")))
            if self._in_collection(entity, normalized)
        ]

    def known_collections_of(self, type_name: str) -> list[str]:
        return sorted(
            {
                str(entity.get("collection"))
                for entity in self.entities.values()
                if entity.get("type") == type_name
            }
        )

    def add(self, entity: dict[str, Any]) -> Result[dict[str, Any], AnalysisInputError]:
        failure = self._validate(entity)
        if failure is not None:
            return err(failure)
        key = self._key(entity)
        if key in self.entities:
            return err(
                AnalysisInputError(message="entity already exists", operation="environment-state")
            )
        self.entities[key] = copy.deepcopy(entity)
        return ok(copy.deepcopy(entity))

    def merge(self, entity: dict[str, Any]) -> Result[dict[str, Any], AnalysisInputError]:
        failure = self._validate(entity)
        if failure is not None:
            return err(failure)
        key = self._key(entity)
        if key not in self.entities:
            return err(
                AnalysisInputError(message="entity does not exist", operation="environment-state")
            )
        self.entities[key] = copy.deepcopy(entity)
        return ok(copy.deepcopy(entity))

    def delete(self, collection: str, entity_id: str) -> bool:
        normalized = normalized_path(collection)
        for key, entity in list(self.entities.items()):
            if self._in_collection(entity, normalized) and str(entity.get("id")) == str(entity_id):
                del self.entities[key]
                return True
        return False

    def document(self, tool: str) -> dict[str, Any] | None:
        return copy.deepcopy(self.documents.get(tool))

    def set_document(self, document: dict[str, Any]) -> Result[dict[str, Any], AnalysisInputError]:
        tool = document.get("tool")
        if not isinstance(tool, str) or not isinstance(document.get("value"), (dict, list)):
            return err(
                AnalysisInputError(message="invalid state document", operation="environment-state")
            )
        self.documents[tool] = copy.deepcopy(document)
        return ok(copy.deepcopy(document))

    def reset(self) -> None:
        self.entities = copy.deepcopy(self.initial_entities)
        self.documents = copy.deepcopy(self.initial_documents)

    def snapshot(self) -> dict[str, Any]:
        return {
            "entities": [copy.deepcopy(entity) for entity in self.entities.values()],
            "documents": [copy.deepcopy(document) for document in self.documents.values()],
            "write_clock": self.write_clock,
        }

    def digest(self) -> str:
        return canonical_json(self.snapshot())


__all__ = ["EnvironmentStateStore"]
