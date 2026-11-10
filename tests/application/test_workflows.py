import json
from pathlib import Path
from types import SimpleNamespace

from rea_mcp.application.workflows import (
    batch_decompile,
    compare_bundles,
    compare_process_captures,
    get_evidence_bundle,
    verify_reconstruction,
    verify_unknown_resolution,
)
from rea_mcp.composition.factories import create_binary_session
from rea_mcp.config.settings import AppConfig
from rea_mcp.domain.reconstruction import Obligation, build_ledger


def _session():  # type: ignore[no-untyped-def]
    return create_binary_session(AppConfig())


def test_get_evidence_bundle(elf_file: Path) -> None:
    session = _session()
    session.open(str(elf_file))
    session.execute("inspect_binary_layout", {})
    summary = get_evidence_bundle(session)
    assert summary["kind"] == "bundle"
    assert summary["record_count"] == 1
    bundle = get_evidence_bundle(session, full=True)
    assert bundle["records"]
    assert bundle["records"][0]["evidence_id"].startswith("ev_")


def test_verify_reconstruction() -> None:
    ledger = build_ledger(
        [Obligation(name="main", required_facets=["pseudo"], provided_facets=["pseudo"])]
    )
    result = verify_reconstruction(ledger.model_dump())
    assert result["verified"] is True
    assert result["coverage"] == 1.0


def test_verify_unknown_resolution(elf_file: Path) -> None:
    session = _session()
    recorded = session.record_unknown("What is main?", "behavior")
    assert recorded.ok
    unknown_id = recorded.value["unknown_id"]
    assert verify_unknown_resolution(session, unknown_id)["verified"] is False
    updated = session.update_unknown(
        unknown_id,
        "resolved",
        resolution={"disposition": "verified", "rationale": "entry confirmed"},
    )
    assert updated.ok
    assert verify_unknown_resolution(session, unknown_id)["verified"] is True


def test_compare_bundles_and_process_captures(tmp_path: Path) -> None:
    left = tmp_path / "left.json"
    right = tmp_path / "right.json"
    left.write_text(
        json.dumps(
            {"records": [{"evidence_id": "ev_1", "operation": "a", "normalized_result": {"x": 1}}]}
        )
    )
    right.write_text(
        json.dumps(
            {
                "records": [
                    {"evidence_id": "ev_1", "operation": "a", "normalized_result": {"x": 2}},
                    {"evidence_id": "ev_2", "operation": "b", "normalized_result": {}},
                ]
            }
        )
    )
    compared = compare_bundles(str(left), str(right))
    assert compared["status"] == "changed"
    assert compared["added"] == ["ev_2"]
    assert compared["changed"] == ["ev_1"]

    capture_a = tmp_path / "a.json"
    capture_b = tmp_path / "b.json"
    capture_a.write_text(json.dumps({"exit_code": 0, "stdout": "hi", "stderr": ""}))
    capture_b.write_text(json.dumps({"exit_code": 1, "stdout": "hi", "stderr": "boom"}))
    captures = compare_process_captures(str(capture_a), str(capture_b))
    assert captures["status"] == "changed"
    assert set(captures["changes"]) == {"exit_code", "stderr"}


def test_batch_decompile_truncates_per_function() -> None:
    class _Result:
        ok = True
        value = SimpleNamespace(normalized_result={"pseudocode": "x" * 1000})

    class _Session:
        def execute(self, operation: str, parameters: dict[str, object]) -> _Result:
            return _Result()

    capped = batch_decompile(_Session(), ["f"], max_bytes_per_function=100)
    entry = capped["functions"][0]
    assert entry["pseudocode"] == "x" * 100
    assert entry["pseudocode_bytes"] == 1000
    assert entry["pseudocode_truncated"] is True

    full = batch_decompile(_Session(), ["f"], max_bytes_per_function=0)
    assert full["functions"][0]["pseudocode"] == "x" * 1000
    assert full["functions"][0]["pseudocode_truncated"] is False


def test_find_changed_behavior_and_correlation(tmp_path: Path) -> None:
    from rea_mcp.application.workflows import (
        correlate_static_and_runtime,
        find_changed_behavior,
    )

    left = tmp_path / "left.json"
    right = tmp_path / "right.json"
    left.write_text(
        json.dumps(
            {
                "records": [
                    {"evidence_id": "ev_1", "operation": "inspect", "normalized_result": {"x": 1}},
                    {"evidence_id": "ev_2", "operation": "capture", "normalized_result": {}},
                ]
            }
        )
    )
    right.write_text(
        json.dumps(
            {
                "records": [
                    {"evidence_id": "ev_1", "operation": "inspect", "normalized_result": {"x": 2}},
                    {"evidence_id": "ev_3", "operation": "capture", "normalized_result": {}},
                ]
            }
        )
    )
    changed = find_changed_behavior(str(left), str(right))
    assert changed["changed_behaviors"] == [{"evidence_id": "ev_1", "operation": "inspect"}]
    correlated = correlate_static_and_runtime(str(left), str(right))
    assert correlated["shared_operations"] == ["capture", "inspect"]
    assert correlated["left_count"] == 2


def test_compare_functions_and_trace(tmp_path: Path) -> None:
    from rea_mcp.application.workflows import (
        compare_functions,
        trace_feature,
        trace_native_values,
    )

    left = tmp_path / "left.json"
    right = tmp_path / "right.json"
    left.write_text(
        json.dumps(
            {
                "records": [
                    {
                        "operation": "function",
                        "normalized_result": {"functions": [{"name": "main"}, {"name": "old"}]},
                    }
                ]
            }
        )
    )
    right.write_text(
        json.dumps(
            {
                "records": [
                    {
                        "operation": "list_procedures",
                        "normalized_result": {"procedures": [{"name": "main"}, {"name": "new"}]},
                    }
                ]
            }
        )
    )
    compared = compare_functions(str(left), str(right))
    assert compared["added"] == ["new"]
    assert compared["removed"] == ["old"]

    class Session:
        def execute(self, operation, parameters):
            return SimpleNamespace(
                ok=True,
                value=SimpleNamespace(
                    normalized_result={"operation": operation, "parameters": parameters}
                ),
            )

    feature = trace_feature(Session(), "token")
    assert feature["feature"] == "token"
    assert feature["strings"]["operation"] == "search_strings"
    native = trace_native_values(Session(), "cookie")
    assert native["query"] == "cookie"
    assert native["matches"]["operation"] == "search"


def test_call_graph_and_path() -> None:
    from rea_mcp.application.workflows import build_call_path, get_call_graph

    class Session:
        def execute(self, operation, parameters):
            if operation == "function":
                rows = [{"name": "a"}, {"name": "b"}, {"name": "c"}]
                return SimpleNamespace(
                    ok=True, value=SimpleNamespace(normalized_result={"functions": rows})
                )
            name = parameters.get("function")
            refs = {
                "a": [],
                "b": [{"from": "a", "to": "b", "type": "call"}],
                "c": [{"from": "b", "to": "c", "type": "call"}],
            }[name]
            return SimpleNamespace(
                ok=True, value=SimpleNamespace(normalized_result={"xrefs": refs})
            )

    graph = get_call_graph(Session(), limit=10)
    assert graph["function_count"] == 3
    assert len(graph["edges"]) == 2
    path = build_call_path(Session(), "a", "c")
    assert path["found"] is True
    assert path["path"] == ["a", "b", "c"]
    missing = build_call_path(Session(), "c", "a")
    assert missing["found"] is False
