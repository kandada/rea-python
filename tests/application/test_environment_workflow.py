from __future__ import annotations

from rea_mcp.application.environment.workflow import prepare_environment


def _manifest() -> dict:
    return {
        "evidence_id": "ev_manifest",
        "normalized_result": {
            "kind": "environment-manifest",
            "parent_evidence_id": "ev_capture",
            "name": "demo",
            "tools": [
                {
                    "name": "get_item",
                    "method": "GET",
                    "path_template": "/api/items/{id}",
                    "parameters": {"id": "path"},
                    "record_ordinals": [0],
                },
                {
                    "name": "health",
                    "method": "GET",
                    "path_template": "/health",
                    "parameters": {},
                    "record_ordinals": [1],
                },
            ],
        },
    }


def _capture() -> dict:
    return {
        "evidence_id": "ev_capture",
        "normalized_result": {
            "kind": "environment-capture",
            "artifact": {"sha256": "a" * 64},
            "entries": [
                {
                    "request": {"method": "GET", "url": "https://x/api/items/1"},
                    "response": {
                        "status": 200,
                        "content": {"mimeType": "application/json", "text": '{"id":"1"}'},
                    },
                },
                {
                    "request": {"method": "GET", "url": "https://x/health"},
                    "response": {
                        "status": 200,
                        "content": {"mimeType": "text/plain", "text": "ok"},
                    },
                },
            ],
        },
    }


def test_prepare_environment_derives_state_and_bundle() -> None:
    result = prepare_environment(_manifest(), _capture())
    assert result.ok
    prepared = result.value
    assert prepared.coverage["entity_count"] == 1
    assert prepared.bundle.tool_count == 2
    assert prepared.bundle.check == {"tool": "health", "status": 200, "recordOrdinal": 1}
    assert any(file.path == "envs/demo/Dockerfile" for file in prepared.bundle.files)
