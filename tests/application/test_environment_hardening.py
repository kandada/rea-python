from __future__ import annotations

from pathlib import Path

from rea_mcp.application.environment.bundle import (
    plan_environment_bundle,
    validate_bundle_name,
    write_environment_bundle,
)
from rea_mcp.application.environment.compare import compare_environment
from rea_mcp.application.environment.extract import extract_state
from rea_mcp.application.environment.source import (
    EnvironmentSource,
    RecordedExchange,
    load_environment_source,
    load_probe_exchanges,
    replayed_body,
)
from rea_mcp.application.environment.state_document import EnvironmentState, parse_state_document
from rea_mcp.application.environment.state_store import EnvironmentStateStore
from rea_mcp.application.environment.writes import (
    apply_write,
    delete_entity,
    merge_entity,
    set_document,
)


def _manifest() -> dict:
    return {
        "evidence_id": "ev_m",
        "normalized_result": {
            "kind": "environment-manifest",
            "parent_evidence_id": "ev_c",
            "name": "demo",
            "tools": [
                {
                    "name": "get_item",
                    "method": "GET",
                    "path_template": "/api/items/{id}",
                    "record_ordinals": [0],
                }
            ],
        },
    }


def _capture(entries: list[dict] | None = None) -> dict:
    return {
        "evidence_id": "ev_c",
        "normalized_result": {
            "kind": "environment-capture",
            "artifact": {"sha256": "a" * 64},
            "entries": entries
            if entries is not None
            else [
                {
                    "request": {"method": "GET", "url": "https://x/api/items/1"},
                    "response": {
                        "status": 200,
                        "content": {"mimeType": "application/json", "text": '{"id":"1"}'},
                    },
                }
            ],
        },
    }


def _state() -> EnvironmentState:
    return EnvironmentState(
        evidence_id="ev",
        types=[
            {
                "collection_template": "/api/items/{id}",
                "id_field": "id",
                "id_basis": "path-parameter",
                "init_before_ordinal": None,
                "volatile_fields": [],
            }
        ],
        views={
            "get_item": {"shape": "item", "type": "/api/items/{id}", "tool": "get_item"},
            "config": {"shape": "document", "tool": "config"},
        },
        entities=[
            {
                "type": "/api/items/{id}",
                "collection": "/api/items/1",
                "id": "1",
                "fields": {"id": "1", "name": "one"},
                "view_fields": [{"tool": "get_item", "fields": {"id": "1", "name": "one"}}],
                "record_ordinals": [0],
            }
        ],
        documents=[{"tool": "config", "path": "/config", "value": {"a": 1}, "record_ordinal": 1}],
    )


def _document() -> dict:
    return {
        "rea_state": {
            "version": 1,
            "state_evidence_id": "ev",
            "entities": [
                {
                    "type": "/api/items/{id}",
                    "collection": "/api/items/1",
                    "id": "1",
                    "fields": {"id": "1", "name": "one"},
                    "view_fields": [{"tool": "get_item", "fields": {"id": "1", "name": "one"}}],
                    "record_ordinals": [0],
                }
            ],
            "documents": [{"tool": "config", "path": "/config", "value": {"a": 1}}],
        }
    }


def _store() -> EnvironmentStateStore:
    return EnvironmentStateStore.from_state(_state())


def test_source_rejects_non_manifest_and_missing_evidence_id() -> None:
    assert not load_environment_source({}, _capture()).ok
    manifest = _manifest()
    del manifest["evidence_id"]
    assert not load_environment_source(manifest, _capture()).ok


def test_source_accepts_permissive_har_and_request_fallbacks() -> None:
    har = {
        "evidence_id": "ev_c",
        "normalized_result": {
            "kind": "environment-capture",
            "capture_format": "har",
            "artifact": {"sha256": "b" * 64},
            "requests": [{"url": "https://x/health?full=1", "status": 204}],
        },
    }
    loaded = load_environment_source(_manifest(), har)
    assert loaded.ok
    assert loaded.value.evidence_id == "ev_c"
    assert loaded.value.capture_sha256 == "b" * 64


def test_replayed_body_handles_invalid_base64_cut_and_non_json() -> None:
    invalid = replayed_body(
        RecordedExchange(0, "/x", None, 200, "application/json", "!!!!", "base64")
    )
    assert invalid == {"kind": "base64", "encoded": "!!!!", "whole": True}
    cut = replayed_body(
        RecordedExchange(1, "/x", None, 200, "application/json", "{", body_cut=True)
    )
    assert cut == {"kind": "cut", "text": "{"}
    text = replayed_body(RecordedExchange(2, "/x", None, 200, "text/plain", "{not json"))
    assert text == {"kind": "text", "text": "{not json"}
    json_body = replayed_body(
        RecordedExchange(3, "/x", None, 200, "application/json; charset=utf-8", '{"a":1}')
    )
    assert json_body == {"kind": "json", "value": {"a": 1}}


def test_probe_loader_accepts_capture_and_raw_har() -> None:
    assert len(load_probe_exchanges(_capture())) == 1
    raw = {"normalized_result": {"kind": "environment-capture", "entries": []}}
    assert load_probe_exchanges(raw) == []
    assert load_probe_exchanges(None) == []


def test_compare_marks_ambiguous_probes_unknown_and_detects_content_type() -> None:
    source = EnvironmentSource(
        manifest={},
        manifest_evidence_id="ev_m",
        evidence_id="ev_c",
        capture_kind="environment-capture",
        capture_sha256=None,
        exchanges={
            0: RecordedExchange(0, "/api", None, 200, "application/json", "{}"),
            1: RecordedExchange(1, "/api", None, 200, "application/json", "{}"),
            2: RecordedExchange(2, "/other", None, 200, "text/plain", "x"),
        },
    )
    probe = RecordedExchange(9, "/api", None, 200, "text/plain", "x")
    result = compare_environment(source, [probe])
    assert result["unknown_count"] == 1
    assert result["coverage"]["unknown_paths"] == ["/api"]
    changed = compare_environment(
        source, [RecordedExchange(1, "/other", None, 500, "text/plain", "x")]
    )
    assert changed["changed_count"] == 1


def test_state_document_rejects_version_extra_and_bad_arrays() -> None:
    for mutate in (
        lambda document: document["rea_state"].__setitem__("version", 2),
        lambda document: document["rea_state"].__setitem__("extra", True),
        lambda document: document["rea_state"].__setitem__("entities", {}),
    ):
        document = _document()
        mutate(document)
        assert not parse_state_document(_state(), document).ok


def test_state_document_rejects_unknown_type_and_view_mismatch() -> None:
    document = _document()
    document["rea_state"]["entities"][0]["type"] = "/api/other/{id}"
    assert not parse_state_document(_state(), document).ok
    document = _document()
    document["rea_state"]["entities"][0]["view_fields"][0]["tool"] = "config"
    assert not parse_state_document(_state(), document).ok


def test_state_document_rejects_unknown_document_and_ordinal_mismatch() -> None:
    document = _document()
    document["rea_state"]["documents"][0]["tool"] = "missing"
    assert not parse_state_document(_state(), document).ok
    document = _document()
    document["rea_state"]["entities"][0]["view_fields"] = []
    document["rea_state"]["entities"][0]["record_ordinals"] = [99]
    assert not parse_state_document(_state(), document).ok


def test_store_rejects_unknown_type_collection_and_missing_merge() -> None:
    store = _store()
    unknown = store.add(
        {
            "type": "/unknown/{id}",
            "collection": "/unknown/1",
            "id": "1",
            "fields": {"id": "1"},
            "view_fields": [],
            "record_ordinals": [],
        }
    )
    assert not unknown.ok
    mismatch = store.add(
        {
            "type": "/api/items/{id}",
            "collection": "/api/nope/1",
            "id": "1",
            "fields": {"id": "1"},
            "view_fields": [],
            "record_ordinals": [],
        }
    )
    assert not mismatch.ok
    assert not store.merge(
        {
            "type": "/api/items/{id}",
            "collection": "/api/items/9",
            "id": "9",
            "fields": {"id": "9"},
            "view_fields": [],
            "record_ordinals": [],
        }
    ).ok


def test_store_ordering_delete_document_validation_and_digest_changes() -> None:
    store = _store()
    for entity_id in ("3", "2"):
        assert store.add(
            {
                "type": "/api/items/{id}",
                "collection": f"/api/items/{entity_id}",
                "id": entity_id,
                "fields": {"id": entity_id},
                "view_fields": [],
                "record_ordinals": [],
            }
        ).ok
    assert [item["id"] for item in store.list_entities("/api/items")] == ["1", "2", "3"]
    before = store.digest()
    assert store.delete("/api/items/2", "2")
    assert not store.delete("/api/items/2", "2")
    assert store.digest() != before
    assert not store.set_document({"tool": "config", "value": 1}).ok
    assert not store.set_document({"tool": 1, "value": {}}).ok


def test_write_operations_report_missing_identity_and_documents() -> None:
    store = _store()
    assert not delete_entity(store, "/api/items/1", "9").ok
    assert not merge_entity(store, "/api/items/1", "9", {"name": "x"}).ok
    assert not set_document(store, "missing", {}).ok
    assert set_document(store, "config", {"a": 2}).ok


def test_apply_write_rejects_query_post_and_unsupported_combinations() -> None:
    store = _store()
    query_post = apply_write(store, method="POST", path="/api/search?q=1", body={"id": "2"})
    assert not query_post.ok
    missing_type = apply_write(store, method="POST", path="/other", body={"id": "2"})
    assert not missing_type.ok
    unsupported = apply_write(store, method="PUT", path="/api/items", body={"id": "2"})
    assert not unsupported.ok
    missing = apply_write(store, method="PATCH", path="/api/items/9", body={"name": "x"})
    assert missing.ok and missing.value["applied"] is False


def test_extract_reports_list_without_identity_and_skips_non_json() -> None:
    source = EnvironmentSource(
        manifest={
            "tools": [
                {
                    "name": "list",
                    "method": "GET",
                    "path_template": "/items",
                    "record_ordinals": [0, 1],
                }
            ]
        },
        manifest_evidence_id="ev_m",
        evidence_id="ev_c",
        capture_kind="environment-capture",
        capture_sha256=None,
        exchanges={
            0: RecordedExchange(0, "/items", None, 200, "application/json", '{"data":[{"x":1}]}'),
            1: RecordedExchange(1, "/items", None, 200, "text/plain", "ignored"),
        },
    )
    result = extract_state(source)
    assert result.state.entities == []
    assert any("no identity" in item for item in result.limitations)


def test_bundle_validation_tarball_and_verifier_contents(tmp_path: Path) -> None:
    assert not validate_bundle_name("Bad Name").ok
    assert not validate_bundle_name("con").ok
    plan = plan_environment_bundle(
        {"name": "demo"},
        name="demo",
        package_source={"kind": "tarball", "path": "pkg.tgz"},
        tool_count=2,
        check={"tool": "health", "status": 200},
    )
    assert plan.ok
    dockerfile = next(file.content for file in plan.value.files if file.path.endswith("Dockerfile"))
    assert "rea-agents.tgz" in dockerfile
    verifier = next(file.content for file in plan.value.files if file.path.endswith("verify.py"))
    assert "TOOL_COUNT = 2" in verifier
    assert '"health"' in verifier
    tarball = tmp_path / "pkg.tgz"
    tarball.write_bytes(b"tarball")
    written = write_environment_bundle(
        plan.value,
        tmp_path / "bundle",
        manifest_bytes=b"{}",
        evidence_bytes=b"{}",
        package_tarball=tarball,
    )
    assert written.ok
    assert (tmp_path / "bundle/envs/demo/rea-agents.tgz").read_bytes() == b"tarball"


def test_replayed_body_cuts_oversized_text_and_base64() -> None:
    oversized = replayed_body(
        RecordedExchange(0, "/x", None, 200, "text/plain", "x" * (256 * 1024 + 1))
    )
    assert oversized["kind"] == "cut"
    base64_cut = replayed_body(
        RecordedExchange(1, "/x", None, 200, "application/octet-stream", "eA==", "base64", True)
    )
    assert base64_cut == {"kind": "base64", "encoded": "eA==", "whole": False}


def test_compare_json_key_order_is_unchanged() -> None:
    source = EnvironmentSource(
        manifest={},
        manifest_evidence_id="ev_m",
        evidence_id="ev_c",
        capture_kind="environment-capture",
        capture_sha256=None,
        exchanges={0: RecordedExchange(0, "/api", None, 200, "application/json", '{"a":1,"b":2}')},
    )
    result = compare_environment(
        source, [RecordedExchange(0, "/api", None, 200, "application/json", '{"b":2,"a":1}')]
    )
    assert result["status"] == "unchanged"


def test_state_document_rejects_evidence_and_types_mismatch() -> None:
    document = _document()
    document["rea_state"]["state_evidence_id"] = "other"
    assert not parse_state_document(_state(), document).ok
    document = _document()
    document["rea_state"]["types"] = []
    assert not parse_state_document(_state(), document).ok


def test_extract_nested_list_and_multiple_documents() -> None:
    source = EnvironmentSource(
        manifest={
            "tools": [
                {
                    "name": "list",
                    "method": "GET",
                    "path_template": "/items",
                    "record_ordinals": [0],
                },
                {
                    "name": "config",
                    "method": "GET",
                    "path_template": "/config",
                    "record_ordinals": [1],
                },
                {
                    "name": "about",
                    "method": "GET",
                    "path_template": "/about",
                    "record_ordinals": [2],
                },
            ]
        },
        manifest_evidence_id="ev_m",
        evidence_id="ev_c",
        capture_kind="environment-capture",
        capture_sha256=None,
        exchanges={
            0: RecordedExchange(
                0, "/items", None, 200, "application/json", '{"data":{"items":[{"id":"1"}]}}'
            ),
            1: RecordedExchange(1, "/config", None, 200, "application/json", '{"a":1}'),
            2: RecordedExchange(2, "/about", None, 200, "application/json", '{"b":2}'),
        },
    )
    result = extract_state(source)
    assert any(entity["id"] == "1" for entity in result.state.entities)
    assert {document["tool"] for document in result.state.documents} == {"config", "about"}
