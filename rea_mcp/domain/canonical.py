"""Deterministic (canonical) JSON serialization and semantic digests.

Canonical serialization is the foundation of the Evidence model: the same
semantic content must always produce the same digest, regardless of key order or
Python container type. This mirrors the role of RFC 8785 canonicalization in REA.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .json_value import normalize_json_value


def canonical_json(value: Any) -> str:
    """Serialize ``value`` deterministically.

    - Object keys are sorted by Unicode code point.
    - No insignificant whitespace.
    - Non-ASCII characters are emitted literally (UTF-8), not escaped.
    """

    normalized = normalize_json_value(value)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def digest_canonical(value: Any, namespace: str = "value") -> str:
    """Return the SHA-256 hex digest of the canonical form of ``value``."""

    encoded = canonical_json(value).encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()
    if namespace:
        return digest
    return digest


def prefixed_digest(prefix: str, value: Any) -> str:
    """Return ``"<prefix>_<sha256 hex>"`` for a value."""

    return f"{prefix}_{digest_canonical(value)}"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


__all__ = ["canonical_json", "digest_canonical", "prefixed_digest", "sha256_bytes"]
