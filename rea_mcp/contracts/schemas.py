"""Compact input-schema projection for schema-size-constrained MCP clients.

Some providers reject a tool catalog when a single input schema exceeds a literal
byte cap. :func:`compact_input_schema` drops annotation prose and inlines local
references to fit a budget while preserving property names, types and required
fields. Server-side validation still uses the canonical schema.
"""

from __future__ import annotations

import json
from typing import Any

_DROP_KEYS = {"description", "examples", "title", "default", "$comment", "example"}


def compact_input_schema(schema: dict[str, Any], budget_bytes: int = 13312) -> dict[str, Any]:
    """Return a compacted projection of ``schema`` within ``budget_bytes``."""

    definitions = schema.get("$defs") or schema.get("definitions") or {}
    compacted: dict[str, Any] = _compact(schema, definitions, depth=0)
    if _size(compacted) <= budget_bytes:
        return compacted
    # Fall back to a shallow projection: names, types, required, first-level guidance.
    shallow = _shallow(schema, definitions)
    return shallow


def _compact(node: Any, definitions: dict[str, Any], depth: int) -> Any:
    if depth > 10:
        return {}
    if isinstance(node, list):
        return [_compact(item, definitions, depth + 1) for item in node]
    if not isinstance(node, dict):
        return node
    ref = node.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/$defs/"):
        target = definitions.get(ref.rsplit("/", 1)[-1])
        if isinstance(target, dict):
            return _compact(target, definitions, depth + 1)
    result: dict[str, Any] = {}
    for key, value in node.items():
        if key in _DROP_KEYS or key in ("$defs", "definitions"):
            continue
        result[key] = _compact(value, definitions, depth + 1)
    return result


def _shallow(schema: dict[str, Any], definitions: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if "description" in schema:
        result["description"] = schema["description"]
    if "type" in schema:
        result["type"] = schema["type"]
    if "required" in schema:
        result["required"] = schema["required"]
    properties = schema.get("properties")
    if isinstance(properties, dict):
        result["properties"] = {
            name: _resolve_type(value, definitions) for name, value in properties.items()
        }
    return result


def _resolve_type(node: Any, definitions: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(node, dict):
        return {}
    ref = node.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/$defs/"):
        node = definitions.get(ref.rsplit("/", 1)[-1], {})
        if not isinstance(node, dict):
            return {}
    out: dict[str, Any] = {}
    if "type" in node:
        out["type"] = node["type"]
    if "anyOf" in node:
        out["anyOf"] = [
            {"type": item.get("type")} for item in node["anyOf"] if isinstance(item, dict)
        ]
    return out


def _size(value: Any) -> int:
    return len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


__all__ = ["compact_input_schema"]
