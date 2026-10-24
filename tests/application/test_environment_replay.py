from __future__ import annotations

from rea_mcp.application.environment.replay import replay_tool
from rea_mcp.application.environment.source import EnvironmentSource, RecordedExchange


def _source() -> EnvironmentSource:
    return EnvironmentSource(
        manifest={
            "tools": [
                {
                    "name": "get_item",
                    "method": "GET",
                    "path_template": "/api/items/{p1}",
                    "parameters": {"p1": "path", "q": "query"},
                }
            ]
        },
        manifest_evidence_id="ev_m",
        evidence_id="ev_c",
        capture_kind="web-network-capture",
        capture_sha256=None,
        exchanges={
            0: RecordedExchange(0, "/api/items/1", "?q=a", 200, "application/json", '{"id":1}'),
            1: RecordedExchange(1, "/api/items/1", "?q=b", 404, "text/plain", "no"),
        },
    )


def test_replay_selects_path_and_query() -> None:
    answer = replay_tool(_source(), "get_item", {"p1": "1", "q": "a"})
    assert answer.ok
    assert answer.record_ordinal == 0
    assert answer.body == {"kind": "json", "value": {"id": 1}}
    missing = replay_tool(_source(), "get_item", {"p1": "2"})
    assert not missing.ok


def test_replay_missing_path_and_tool() -> None:
    assert not replay_tool(_source(), "get_item", {}).ok
    assert not replay_tool(_source(), "missing", {}).ok
