"""Shared bounded paging helpers for provider result projections."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, TypeVar

T = TypeVar("T")


def page_sequence(items: Sequence[T], *, offset: int = 0, limit: int = 500) -> dict[str, Any]:
    total = len(items)
    offset = max(0, offset)
    limit = min(10_000, max(1, limit))
    start = min(offset, total)
    page = list(items[start : start + limit])
    return {
        "items": page,
        "total": total,
        "offset": start,
        "next_offset": start + len(page) if start + len(page) < total else None,
    }


def page_lines(text: str, *, offset: int = 0, limit: int = 500) -> dict[str, Any]:
    lines = text.splitlines(keepends=True)
    page = page_sequence(lines, offset=offset, limit=limit)
    page["text"] = "".join(page.pop("items"))
    page["line_total"] = page.pop("total")
    return page
