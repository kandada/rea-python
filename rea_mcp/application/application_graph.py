"""Small authenticated JavaScript application-graph workflows."""

from __future__ import annotations

from typing import Any, cast

from ..domain.binary_target import parse_binary_target
from ..providers.javascript import JavaScriptApplicationProvider


def _graph(path: str) -> dict[str, Any]:
    target = parse_binary_target(path)
    if not target.ok:
        raise target.error
    result = JavaScriptApplicationProvider().analyze(
        "analyze_javascript_application",
        target.value,
        {"module_limit": 10_000, "edge_limit": 10_000},
        None,
    )
    if not result.ok:
        raise result.error
    return cast("dict[str, Any]", result.value.result)


def compare_application_versions(left: str, right: str) -> dict[str, Any]:
    left_graph = _graph(left)
    right_graph = _graph(right)
    left_modules = left_graph.get("modules") or {}
    right_modules = right_graph.get("modules") or {}
    added = sorted(right_modules.keys() - left_modules.keys())
    removed = sorted(left_modules.keys() - right_modules.keys())
    changed = [
        name
        for name in sorted(left_modules.keys() & right_modules.keys())
        if left_modules[name] != right_modules[name]
    ]
    left_edges = {(edge.get("from"), edge.get("to")) for edge in left_graph.get("edges") or []}
    right_edges = {(edge.get("from"), edge.get("to")) for edge in right_graph.get("edges") or []}
    return {
        "status": "changed" if added or removed or changed else "unchanged",
        "modules": {
            "added": added,
            "removed": removed,
            "changed": changed,
            "added_count": len(added),
            "removed_count": len(removed),
            "changed_count": len(changed),
        },
        "edges": {
            "added": sorted(right_edges - left_edges),
            "removed": sorted(left_edges - right_edges),
        },
        "limitations": (
            "Static module names/imports only; runtime behavior and fuzzy pairing are not inferred.",
        ),
    }


def trace_application_feature(path: str, feature: str) -> dict[str, Any]:
    graph = _graph(path)
    needle = feature.lower()
    matches = []
    for name, module in (graph.get("modules") or {}).items():
        imports = module.get("imports") or []
        if needle in name.lower() or any(needle in str(item).lower() for item in imports):
            matches.append(
                {
                    "module": name,
                    "kind": "module",
                    "imports": imports[:32],
                }
            )
    edges = [
        edge
        for edge in graph.get("edges") or []
        if needle in str(edge.get("from", "")).lower() or needle in str(edge.get("to", "")).lower()
    ]
    return {
        "feature": feature,
        "match_count": len(matches) + len(edges),
        "modules": matches[:128],
        "edges": edges[:128],
        "status": "matched" if matches or edges else "unknown",
        "limitations": (
            "Regex/static graph search only; dynamic names and runtime-only routes remain unknown.",
        ),
    }


def trace_javascript_semantics(path: str, node: str) -> dict[str, Any]:
    graph = _graph(path)
    modules = graph.get("modules") or {}
    module = next((name for name in modules if name == node or name.endswith(node)), None)
    if module is None:
        return {
            "node": node,
            "status": "unknown",
            "outgoing": [],
            "incoming": [],
            "limitations": ("No exact/suffix module match was observed.",),
        }
    outgoing = [edge for edge in graph.get("edges") or [] if edge.get("from") == module]
    incoming = [edge for edge in graph.get("edges") or [] if edge.get("to") == module]
    return {
        "node": module,
        "status": "observed",
        "imports": (modules.get(module) or {}).get("imports") or [],
        "outgoing": outgoing,
        "incoming": incoming,
        "limitations": (
            "Static import graph only; data flow, closure semantics and runtime behavior are not decoded.",
        ),
    }


def compare_source_to_bundle(source: str, bundle: str) -> dict[str, Any]:
    return compare_application_versions(source, bundle)


def compare_javascript_export_shapes(
    left: str, right: str, module: str, export_name: str
) -> dict[str, Any]:
    left_graph = _graph(left)
    right_graph = _graph(right)
    left_module = (left_graph.get("modules") or {}).get(module)
    right_module = (right_graph.get("modules") or {}).get(module)
    if left_module is None or right_module is None:
        return {
            "module": module,
            "export": export_name,
            "status": "unknown",
            "limitations": ("The selected module was not observed on both sides.",),
        }
    left_imports = left_module.get("imports") or []
    right_imports = right_module.get("imports") or []
    changed = left_module.get("size") != right_module.get("size") or left_imports != right_imports
    return {
        "module": module,
        "export": export_name,
        "status": "changed" if changed else "unchanged",
        "left": {"size": left_module.get("size"), "imports": left_imports[:64]},
        "right": {"size": right_module.get("size"), "imports": right_imports[:64]},
        "limitations": (
            "Only module presence, size and imports are available; return-property shapes are not decoded.",
        ),
    }


__all__ = [
    "compare_application_versions",
    "compare_javascript_export_shapes",
    "compare_source_to_bundle",
    "trace_application_feature",
    "trace_javascript_semantics",
]
