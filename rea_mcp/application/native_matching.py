"""Exact-name native export matching between two binaries."""

from __future__ import annotations

from typing import Any

from ..domain.binary_target import parse_binary_target
from ..providers.native_exports import NativeExportsProvider


def match_native_functions(
    left: str, right: str, query: str | None = None, limit: int = 100
) -> dict[str, Any]:
    left_rows = _exports(left)
    right_rows = _exports(right)
    if query:
        needle = query.lower()
        left_rows = [row for row in left_rows if needle in str(row.get("name", "")).lower()]
        right_rows = [row for row in right_rows if needle in str(row.get("name", "")).lower()]
    left_by_name = {row["name"]: row for row in left_rows if row.get("name")}
    right_by_name = {row["name"]: row for row in right_rows if row.get("name")}
    matched = []
    for name in sorted(left_by_name.keys() & right_by_name.keys()):
        matched.append(
            {
                "name": name,
                "left": left_by_name[name],
                "right": right_by_name[name],
                "same_address": left_by_name[name].get("value") == right_by_name[name].get("value"),
            }
        )
    return {
        "query": query,
        "matched": matched[: max(1, limit)],
        "matched_count": len(matched),
        "added": [
            right_by_name[name] for name in sorted(right_by_name.keys() - left_by_name.keys())
        ][: max(1, limit)],
        "removed": [
            left_by_name[name] for name in sorted(left_by_name.keys() - right_by_name.keys())
        ][: max(1, limit)],
        "left_export_count": len(left_rows),
        "right_export_count": len(right_rows),
        "limitations": (
            "Matching is exact exported name only; stripped/local functions and semantic similarity are not inferred.",
        ),
    }


def _exports(path: str) -> list[dict[str, Any]]:
    parsed = parse_binary_target(path)
    if not parsed.ok:
        raise parsed.error
    result = NativeExportsProvider().analyze("inspect_native_exports", parsed.value, {}, None)
    if not result.ok:
        raise result.error
    return list(result.value.result.get("exports") or [])


__all__ = ["match_native_functions"]
