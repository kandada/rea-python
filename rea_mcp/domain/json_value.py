"""JSON value validation and normalization.

REA-Python stores provider results as plain JSON. This module validates a candidate
value is JSON-compatible (string keys, finite numbers, bounded depth) and
normalizes Python-specific types into their JSON equivalents, so that downstream
canonical serialization and digests are deterministic.
"""

from __future__ import annotations

import math
from typing import Any

JsonValue = Any
MAX_JSON_DEPTH = 64


class JsonValueError(ValueError):
    """Raised when a value cannot be represented as JSON."""


def validate_json_value(value: Any, *, path: str = "$", depth: int = 0) -> None:
    """Raise :class:`JsonValueError` if ``value`` is not a valid JSON value."""

    if depth > MAX_JSON_DEPTH:
        raise JsonValueError(f"JSON value exceeds max depth {MAX_JSON_DEPTH} at {path}")
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise JsonValueError(f"Non-finite number at {path}: {value!r}")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            validate_json_value(item, path=f"{path}[{index}]", depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise JsonValueError(f"Non-string object key at {path}: {key!r}")
            validate_json_value(item, path=f"{path}.{key}", depth=depth + 1)
        return
    raise JsonValueError(f"Unsupported JSON value type at {path}: {type(value).__name__}")


def normalize_json_value(value: Any) -> JsonValue:
    """Return a JSON-safe copy of ``value``, converting tuples to lists.

    Raises :class:`JsonValueError` for values that cannot be represented.
    """

    validate_json_value(value)
    return _normalize(value)


def _normalize(value: Any) -> JsonValue:
    if isinstance(value, bool) or value is None or isinstance(value, (int, str)):
        return value
    if isinstance(value, float):
        # Normalize -0.0 to 0.0 for deterministic digests.
        return 0.0 if value == 0 else value
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    if isinstance(value, dict):
        return {key: _normalize(item) for key, item in value.items()}
    raise JsonValueError(f"Unsupported JSON value type: {type(value).__name__}")


__all__ = [
    "MAX_JSON_DEPTH",
    "JsonValue",
    "JsonValueError",
    "normalize_json_value",
    "validate_json_value",
]
