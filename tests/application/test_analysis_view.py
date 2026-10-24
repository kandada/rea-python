import json
from pathlib import Path

from rea_mcp.application.analysis_view import load_view
from rea_mcp.composition.factories import create_binary_session
from rea_mcp.config.settings import AppConfig


def _bundle_path(tmp_path: Path, elf_file: Path) -> Path:
    session = create_binary_session(AppConfig())
    session.open(str(elf_file))
    session.execute("inspect_binary_layout")
    bundle = session.export_bundle()
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    return path


def test_summarize_bundle(tmp_path: Path, elf_file: Path) -> None:
    view = load_view(_bundle_path(tmp_path, elf_file), "summary")
    assert view.ok
    assert view.value["kind"] == "bundle"
    assert view.value["record_count"] == 1
    assert view.value["operations"] == {"inspect_binary_layout": 1}


def test_record_source(tmp_path: Path, elf_file: Path) -> None:
    bundle_path = _bundle_path(tmp_path, elf_file)
    bundle = json.loads(bundle_path.read_text())
    record_path = tmp_path / "record.json"
    record_path.write_text(json.dumps(bundle["records"][0]), encoding="utf-8")
    view = load_view(record_path, "summary")
    assert view.ok
    assert view.value["kind"] == "record"
    assert view.value["operation"] == "inspect_binary_layout"


def test_missing_source_is_error(tmp_path: Path) -> None:
    assert not load_view(tmp_path / "missing.json").ok


def _har_record() -> dict:
    return {
        "evidence_id": "ev_har",
        "operation": "inspect_network_capture",
        "normalized_result": {
            "requests": [
                {
                    "method": "GET",
                    "url": "https://api.example.com/v1/items/123?q=a",
                    "status": 200,
                    "mime_type": "application/json",
                },
                {
                    "method": "GET",
                    "url": "https://api.example.com/v1/items/456?q=b",
                    "status": 404,
                    "mime_type": "application/json",
                },
                {
                    "method": "POST",
                    "url": "https://api.example.com/v1/items",
                    "status": 201,
                    "mime_type": "application/json",
                },
            ]
        },
    }


def _js_record() -> dict:
    return {
        "evidence_id": "ev_js",
        "operation": "analyze_javascript_application",
        "normalized_result": {
            "modules": {
                "main.js": {"size": 10, "imports": ["./a"]},
                "a.js": {"size": 5, "imports": []},
            },
            "edges": [{"from": "main.js", "to": "./a"}],
        },
    }


def test_environment_manifest_view(tmp_path: Path) -> None:
    path = tmp_path / "har.json"
    path.write_text(json.dumps(_har_record()), encoding="utf-8")
    view = load_view(path, "environment-manifest")
    assert view.ok
    data = view.value
    assert data["kind"] == "environment-manifest"
    assert data["parent_evidence_id"] == "ev_har"
    assert data["tool_count"] == 2
    tools = {tool["name"]: tool for tool in data["tools"]}
    get_tool = next(tool for tool in tools.values() if tool["method"] == "GET")
    assert get_tool["path_template"] == "/v1/items/{p1}"
    assert {(item["name"], item["location"]) for item in get_tool["parameters"]} == {
        ("p1", "path"),
        ("q", "query"),
    }
    assert get_tool["statuses"] == [200, 404]
    post_tool = next(tool for tool in tools.values() if tool["method"] == "POST")
    assert post_tool["body_shape"] is None
    assert any("body" in item.lower() for item in data["unknowns"])


def test_javascript_facts_and_edges(tmp_path: Path) -> None:
    path = tmp_path / "js.json"
    path.write_text(json.dumps(_js_record()), encoding="utf-8")
    facts = load_view(
        path,
        "javascript-facts",
        paths=["main.js"],
        property_keys=["size", "import_count"],
    )
    assert facts.ok
    assert facts.value["rows"] == [{"path": "main.js", "size": 10, "import_count": 1}]
    graph = load_view(path, "javascript", paths=["main.js"])
    assert graph.ok
    assert graph.value["module_count"] == 1
    assert graph.value["edge_total"] == 1


def test_view_selects_record_by_evidence_id(tmp_path: Path) -> None:
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps({"records": [_har_record(), _js_record()]}), encoding="utf-8")
    selected = load_view(path, "environment-manifest", evidence_id="ev_har")
    assert selected.ok
    assert selected.value["parent_evidence_id"] == "ev_har"
    missing = load_view(path, "environment-manifest", evidence_id="ev_missing")
    assert not missing.ok


def test_unknown_view_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "har.json"
    path.write_text(json.dumps(_har_record()), encoding="utf-8")
    view = load_view(path, "everything")
    assert not view.ok


def test_record_view_requires_evidence_id_for_bundle(tmp_path: Path) -> None:
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps({"records": [_har_record()]}), encoding="utf-8")
    assert not load_view(path, "record").ok
    selected = load_view(path, "record", evidence_id="ev_har")
    assert selected.ok
    assert selected.value["evidence_id"] == "ev_har"


def test_record_view_is_budget_guarded(tmp_path: Path) -> None:
    path = tmp_path / "big.json"
    path.write_text(
        json.dumps(
            {
                "evidence_id": "ev_big",
                "operation": "inspect_network_capture",
                "normalized_result": {"blob": "x" * 5000},
            }
        ),
        encoding="utf-8",
    )
    view = load_view(path, "record", budget_bytes=1024)
    assert view.ok
    assert view.value["truncated"] is True
    assert view.value["evidence_reference"]["evidence_id"] == "ev_big"
    assert view.value["summary"]["operation"] == "inspect_network_capture"


def test_environment_manifest_paginates(tmp_path: Path) -> None:
    path = tmp_path / "har.json"
    path.write_text(json.dumps(_har_record()), encoding="utf-8")
    first = load_view(path, "environment-manifest", offset=0, limit=1)
    assert first.ok
    assert first.value["tool_count"] == 2
    assert len(first.value["tools"]) == 1
    assert first.value["next_offset"] == 1
    second = load_view(path, "environment-manifest", offset=1, limit=1)
    assert second.ok
    assert len(second.value["tools"]) == 1
    assert second.value["next_offset"] is None
    assert first.value["tools"][0]["name"] != second.value["tools"][0]["name"]


def test_managed_member_view_pages_collections(tmp_path: Path) -> None:
    record = {
        "evidence_id": "ev_managed",
        "operation": "inspect_managed_members",
        "normalized_result": {
            "types": [{"full_name": "Example.Outer"}],
            "fields": [{"name": "Value", "constant": "literal"}],
            "methods": [
                {"name": "Run", "token": "0x06000001"},
                {"name": "Stop", "token": "0x06000002"},
            ],
            "selection": {"type_names": ["Example.Outer"], "unmatched_type_names": []},
            "coverage": {"state": "complete", "issues": []},
            "metadata": {"status": "complete"},
        },
    }
    path = tmp_path / "managed.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    view = load_view(path, "managed-members", collection="methods", offset=1, limit=1)
    assert view.ok
    data = view.value
    assert data["kind"] == "managed-members"
    assert data["collection"] == "methods"
    assert data["total"] == 2
    assert data["offset"] == 1
    assert data["next_offset"] is None
    assert data["rows"][0]["name"] == "Stop"
    assert data["selection"]["type_names"] == ["Example.Outer"]
    assert not load_view(path, "managed-members", collection="missing").ok


def test_managed_view_requires_collection(tmp_path: Path) -> None:
    path = tmp_path / "managed.json"
    path.write_text(
        json.dumps(
            {
                "evidence_id": "ev_managed",
                "operation": "inspect_managed_members",
                "normalized_result": {"methods": []},
            }
        ),
        encoding="utf-8",
    )
    assert not load_view(path, "managed-members").ok


def test_desktop_application_view_pages(tmp_path: Path) -> None:
    path = tmp_path / "desktop.json"
    path.write_text(
        json.dumps(
            {
                "evidence_id": "ev_desktop",
                "operation": "inspect_desktop_application",
                "normalized_result": {
                    "files": [{"path": "a.dll", "size": 1}, {"path": "b.dll", "size": 2}],
                    "candidates": [{"path": "a.dll", "kind": "dotnet"}],
                    "components": [],
                    "next_probes": [{"operation": "inspect_managed_artifact"}],
                },
            }
        ),
        encoding="utf-8",
    )
    view = load_view(path, "desktop-application", collection="files", offset=1, limit=1)
    assert view.ok
    assert view.value["kind"] == "desktop-application"
    assert view.value["total"] == 2
    assert view.value["rows"][0]["path"] == "b.dll"
