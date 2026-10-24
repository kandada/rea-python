from __future__ import annotations

from rea_mcp.application.environment.source import (
    load_environment_source,
    replayed_body,
)


def _manifest() -> dict:
    return {
        "evidence_id": "ev_manifest",
        "operation": "inspect_analysis_view",
        "normalized_result": {
            "kind": "environment-manifest",
            "parent_evidence_id": "ev_capture",
            "name": "demo",
            "origin": "https://example.test",
            "tools": [
                {
                    "name": "get_item",
                    "method": "GET",
                    "path_template": "/api/items/{p1}",
                    "record_ordinals": [0],
                }
            ],
        },
    }


def _capture() -> dict:
    return {
        "evidence_id": "ev_capture",
        "operation": "inspect_web_network_capture",
        "normalized_result": {
            "kind": "environment-capture",
            "artifact": {"sha256": "a" * 64},
            "entries": [
                {
                    "request": {"method": "GET", "url": "https://example.test/api/items/1?q=x"},
                    "response": {
                        "status": 200,
                        "content": {"mimeType": "application/json", "text": '{"id":1}'},
                    },
                }
            ],
        },
    }


def test_loads_manifest_and_capture_exchanges() -> None:
    result = load_environment_source(_manifest(), _capture())
    assert result.ok
    source = result.value
    assert source.evidence_id == "ev_capture"
    assert source.capture_sha256 == "a" * 64
    exchange = source.exchanges[0]
    assert exchange.path == "/api/items/1"
    assert exchange.query == "?q=x"
    assert exchange.status == 200
    assert replayed_body(exchange) == {"kind": "json", "value": {"id": 1}}


def test_refuses_mismatched_parent() -> None:
    manifest = _manifest()
    manifest["normalized_result"]["parent_evidence_id"] = "ev_other"
    assert not load_environment_source(manifest, _capture()).ok


def test_body_classification_base64_and_cut() -> None:
    from rea_mcp.application.environment.source import RecordedExchange

    base64_body = RecordedExchange(0, "/", None, 200, "text/plain", "aGVsbG8=", "base64")
    assert replayed_body(base64_body)["kind"] == "base64"
    cut = RecordedExchange(0, "/", None, 200, "text/plain", "x" * (300 * 1024), None, True)
    assert replayed_body(cut)["kind"] == "cut"
