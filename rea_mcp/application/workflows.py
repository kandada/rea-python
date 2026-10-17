"""Cross-cutting investigation workflows over Evidence and an open session."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..domain.analysis_error import AnalysisInputError


def get_evidence_bundle(session: Any) -> dict[str, Any]:
    bundle: dict[str, Any] = session.export_bundle()
    return bundle


def verify_reconstruction(ledger: dict[str, Any]) -> dict[str, Any]:
    from ..domain.reconstruction import ReconstructionLedger, evaluate_coverage

    try:
        parsed = ReconstructionLedger.model_validate(ledger)
    except Exception as cause:
        raise AnalysisInputError(operation="verify_reconstruction", message=str(cause)) from cause
    coverage = evaluate_coverage(parsed)
    return {"verified": coverage["complete"], **coverage}


def verify_unknown_resolution(session: Any, unknown_id: str) -> dict[str, Any]:
    unknowns = session.list_unknowns()
    match = next((item for item in unknowns if item.get("unknown_id") == unknown_id), None)
    if match is None:
        return {"unknown_id": unknown_id, "found": False, "verified": False}
    status = match.get("status")
    return {
        "unknown_id": unknown_id,
        "found": True,
        "status": status,
        "verified": status == "resolved",
        "resolution": match.get("resolution"),
    }


def _load_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _evidence_records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        if isinstance(payload.get("records"), list):
            return [item for item in payload["records"] if isinstance(item, dict)]
        if "evidence_id" in payload:
            return [payload]
    return []


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
    ).hexdigest()


def compare_bundles(left: str, right: str) -> dict[str, Any]:
    left_records = {item.get("evidence_id"): item for item in _evidence_records(_load_json(left))}
    right_records = {item.get("evidence_id"): item for item in _evidence_records(_load_json(right))}
    added = sorted(str(key) for key in right_records if key not in left_records)
    removed = sorted(str(key) for key in left_records if key not in right_records)
    changed = sorted(
        str(key)
        for key in left_records.keys() & right_records.keys()
        if _digest(left_records[key].get("normalized_result"))
        != _digest(right_records[key].get("normalized_result"))
    )
    return {
        "status": "unchanged" if not added and not removed and not changed else "changed",
        "left_count": len(left_records),
        "right_count": len(right_records),
        "added": added,
        "removed": removed,
        "changed": changed,
    }


def find_changed_behavior(left: str, right: str) -> dict[str, Any]:
    comparison = compare_bundles(left, right)
    left_records = {item.get("evidence_id"): item for item in _evidence_records(_load_json(left))}
    changed = []
    for evidence_id in comparison["changed"]:
        before = left_records.get(evidence_id, {}).get("operation")
        changed.append({"evidence_id": evidence_id, "operation": before})
    return {**comparison, "changed_behaviors": changed}


def correlate_static_and_runtime(left: str, right: str) -> dict[str, Any]:
    left_records = _evidence_records(_load_json(left))
    right_records = _evidence_records(_load_json(right))
    left_ops = {item.get("operation") for item in left_records}
    right_ops = {item.get("operation") for item in right_records}
    return {
        "static_operations": sorted(str(op) for op in left_ops if op),
        "runtime_operations": sorted(str(op) for op in right_ops if op),
        "shared_operations": sorted(str(op) for op in left_ops & right_ops if op),
        "static_only": sorted(str(op) for op in left_ops - right_ops if op),
        "runtime_only": sorted(str(op) for op in right_ops - left_ops if op),
        "left_count": len(left_records),
        "right_count": len(right_records),
    }


def compare_process_captures(left: str, right: str) -> dict[str, Any]:
    left_payload = _load_json(left)
    right_payload = _load_json(right)
    fields = ("exit_code", "timed_out", "cancelled", "stdout", "stderr")
    changes = {
        field: {"left": left_payload.get(field), "right": right_payload.get(field)}
        for field in fields
        if left_payload.get(field) != right_payload.get(field)
    }
    return {"status": "unchanged" if not changes else "changed", "changes": changes}


def _function_names(records: list[dict[str, Any]]) -> set[str]:
    names: set[str] = set()
    for record in records:
        if record.get("operation") not in ("function", "analyze_function", "list_procedures"):
            continue
        result = record.get("normalized_result") or {}
        for key in ("functions", "procedures"):
            for item in result.get(key, []) or []:
                name = item.get("name") if isinstance(item, dict) else None
                if name:
                    names.add(str(name))
    return names


def compare_functions(left: str, right: str) -> dict[str, Any]:
    left_names = _function_names(_evidence_records(_load_json(left)))
    right_names = _function_names(_evidence_records(_load_json(right)))
    return {
        "status": "unchanged" if left_names == right_names else "changed",
        "left_count": len(left_names),
        "right_count": len(right_names),
        "added": sorted(right_names - left_names),
        "removed": sorted(left_names - right_names),
    }


def _result(session: Any, operation: str, parameters: dict[str, Any]) -> dict[str, Any]:
    result = session.execute(operation, parameters)
    if not result.ok:
        return {"error": result.error.message, "operation": operation}
    return result.value.normalized_result or {}


def batch_decompile(session: Any, functions: list[str]) -> dict[str, Any]:
    results = []
    for name in functions[:50]:
        payload = _result(session, "decompile", {"function": name})
        results.append(
            {
                "function": name,
                "pseudocode": payload.get("pseudocode"),
                "error": payload.get("error"),
            }
        )
    return {"function_count": len(results), "functions": results}


def get_call_graph(session: Any, limit: int = 50) -> dict[str, Any]:
    listing = _result(session, "function", {"limit": limit})
    functions = listing.get("functions", []) if isinstance(listing, dict) else []
    names = [
        str(item.get("name")) for item in functions if isinstance(item, dict) and item.get("name")
    ]
    edges: list[dict[str, Any]] = []
    for name in names[:limit]:
        refs = _result(session, "xrefs", {"function": name, "limit": 50})
        for ref in refs.get("xrefs", []) or []:
            if isinstance(ref, dict):
                edges.append(
                    {
                        "from": ref.get("from"),
                        "to": name,
                        "type": ref.get("type"),
                    }
                )
    return {"functions": names, "edges": edges, "function_count": len(names)}


def build_call_path(
    session: Any, from_function: str, to_function: str, limit: int = 50
) -> dict[str, Any]:
    graph = get_call_graph(session, limit=limit)
    adjacency: dict[str, list[str]] = {}
    for edge in graph["edges"]:
        source = edge.get("from")
        if source:
            adjacency.setdefault(str(source), []).append(str(edge.get("to")))
    queue: list[list[str]] = [[from_function]]
    visited: set[str] = {from_function}
    while queue:
        path = queue.pop(0)
        node = path[-1]
        if node == to_function:
            return {"found": True, "path": path, "from": from_function, "to": to_function}
        for neighbour in adjacency.get(node, []):
            if neighbour not in visited:
                visited.add(neighbour)
                queue.append([*path, neighbour])
    return {"found": False, "path": [], "from": from_function, "to": to_function}


def trace_call_path(
    session: Any, from_function: str, to_function: str, limit: int = 50
) -> dict[str, Any]:
    return build_call_path(session, from_function, to_function, limit=limit)


def trace_feature(session: Any, feature: str) -> dict[str, Any]:
    return {
        "feature": feature,
        "strings": _result(session, "search_strings", {"query": feature, "limit": 50}),
        "procedures": _result(session, "search_procedures", {"query": feature, "limit": 50}),
        "xrefs": _result(session, "find_xrefs_to_name", {"name": feature, "limit": 50}),
    }


def trace_native_values(session: Any, query: str) -> dict[str, Any]:
    return {
        "query": query,
        "strings": _result(session, "search_strings", {"query": query, "limit": 50}),
        "matches": _result(session, "search", {"query": query, "limit": 50}),
    }


__all__ = [
    "batch_decompile",
    "build_call_path",
    "compare_bundles",
    "compare_functions",
    "compare_process_captures",
    "correlate_static_and_runtime",
    "find_changed_behavior",
    "get_call_graph",
    "get_evidence_bundle",
    "trace_call_path",
    "trace_feature",
    "trace_native_values",
    "verify_reconstruction",
    "verify_unknown_resolution",
]
