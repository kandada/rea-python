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
