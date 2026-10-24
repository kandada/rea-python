"""Bounded replay selection for environment manifests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs

from .source import EnvironmentSource, RecordedExchange, replayed_body


@dataclass
class ReplayAnswer:
    ok: bool
    tool: str
    record_ordinal: int | None = None
    status: int | None = None
    content_type: str | None = None
    body: dict[str, Any] | None = None
    evidence_id: str | None = None
    error: str | None = None


def _parameters(tool: dict[str, Any]) -> list[tuple[str, str]]:
    raw = tool.get("parameters") or {}
    if isinstance(raw, dict):
        return [(str(name), str(location)) for name, location in raw.items()]
    if isinstance(raw, list):
        return [
            (str(item.get("name")), str(item.get("location") or "query"))
            for item in raw
            if isinstance(item, dict) and item.get("name")
        ]
    return []


def _call_path(tool: dict[str, Any], args: dict[str, Any]) -> str | None:
    template = str(tool.get("path_template") or "/")
    result = template
    for name, location in _parameters(tool):
        if location != "path":
            continue
        if name not in args:
            return None
        result = result.replace("{" + name + "}", str(args[name]))
    return result


def _call_query(tool: dict[str, Any], args: dict[str, Any]) -> dict[str, list[str]]:
    query = {}
    for name, location in _parameters(tool):
        if location != "query" or name not in args:
            continue
        value = args[name]
        query[name] = [str(value)] if not isinstance(value, list) else [str(item) for item in value]
    return query


def replay_tool(
    source: EnvironmentSource, tool_name: str, args: dict[str, Any] | None = None
) -> ReplayAnswer:
    args = args or {}
    tool = next(
        (item for item in source.manifest.get("tools") or [] if item.get("name") == tool_name), None
    )
    if tool is None:
        return ReplayAnswer(False, tool_name, error="tool is not in the manifest")
    path = _call_path(tool, args)
    if path is None:
        return ReplayAnswer(False, tool_name, error="missing path parameter")
    expected_query = _call_query(tool, args)
    candidates = [
        exchange
        for exchange in source.exchanges.values()
        if exchange.path == path
        and all(
            set(parse_qs((exchange.query or "").lstrip("?"), keep_blank_values=True).get(name, []))
            == set(values)
            for name, values in expected_query.items()
        )
    ]
    if not candidates:
        return ReplayAnswer(False, tool_name, error="no recorded exchange matches the call")
    exchange: RecordedExchange = sorted(candidates, key=lambda item: item.ordinal)[0]
    return ReplayAnswer(
        True,
        tool_name,
        record_ordinal=exchange.ordinal,
        status=exchange.status,
        content_type=exchange.content_type,
        body=replayed_body(exchange),
        evidence_id=source.evidence_id,
    )


__all__ = ["ReplayAnswer", "replay_tool"]
