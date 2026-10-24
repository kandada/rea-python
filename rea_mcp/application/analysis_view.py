"""Projection of saved Evidence into small summaries (token-first delivery)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.result import Result, err, ok


def summarize_record(record: dict[str, Any]) -> dict[str, Any]:
    subject = record.get("subject") or {}
    return {
        "kind": "record",
        "evidence_id": record.get("evidence_id"),
        "operation": record.get("operation"),
        "confidence": record.get("confidence"),
        "authority": record.get("authority"),
        "subject": {
            "format": subject.get("format"),
            "architecture": subject.get("architecture"),
            "sha256": subject.get("sha256"),
        }
        if subject
        else None,
        "provider": (record.get("provider") or {}).get("id"),
        "limitations": record.get("limitations", []),
        "result_keys": sorted(record.get("normalized_result", {}).keys())
        if isinstance(record.get("normalized_result"), dict)
        else None,
    }


def summarize_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    records = bundle.get("records", [])
    operations: dict[str, int] = {}
    for record in records:
        operation = str(record.get("operation", "unknown"))
        operations[operation] = operations.get(operation, 0) + 1
    return {
        "kind": "bundle",
        "schema_version": bundle.get("schema_version"),
        "record_count": len(records),
        "unknown_count": len(bundle.get("unknowns", [])),
        "operations": operations,
        "evidence_ids": [record.get("evidence_id") for record in records],
    }


def page_bundle(bundle: dict[str, Any], offset: int = 0, limit: int = 64) -> dict[str, Any]:
    """Return a stable page of evidence summaries with continuation info."""

    records = bundle.get("records", [])
    ordered = sorted(records, key=lambda record: record.get("evidence_id", ""))
    start = min(max(0, offset), len(ordered))
    page = ordered[start : start + max(0, limit)]
    next_offset = start + len(page) if start + len(page) < len(ordered) else None
    return {
        "kind": "page",
        "total": len(ordered),
        "offset": start,
        "next_offset": next_offset,
        "records": [summarize_record(record) for record in page],
    }


_RECORD_OPERATIONS = {
    "environment-manifest": ("inspect_network_capture", "inspect_web_network_capture"),
    "javascript-facts": ("analyze_javascript_application",),
    "javascript": ("analyze_javascript_application",),
    "managed": ("inspect_managed_artifact",),
    "managed-members": ("inspect_managed_members",),
    "desktop-application": ("inspect_desktop_application",),
}
_ID_SEGMENT_RE = re.compile(
    r"^(?:[0-9]+|[0-9a-fA-F]{8,}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[A-Za-z0-9_-]{16,})$"
)


def _select_record(
    payload: dict[str, Any], view: str, evidence_id: str | None
) -> dict[str, Any] | None:
    if "records" in payload:
        records = [record for record in payload.get("records", []) if isinstance(record, dict)]
        if evidence_id:
            return next((r for r in records if r.get("evidence_id") == evidence_id), None)
        candidates = _RECORD_OPERATIONS.get(view, ())
        for record in reversed(records):
            if record.get("operation") in candidates:
                return record
        return None
    if "evidence_id" in payload:
        if evidence_id and payload.get("evidence_id") != evidence_id:
            return None
        return payload
    return None


def _path_template(path: str) -> tuple[str, list[str]]:
    segments: list[str] = []
    parameters: list[str] = []
    for segment in path.split("/"):
        if not segment:
            continue
        if _ID_SEGMENT_RE.fullmatch(segment):
            name = f"p{len(parameters) + 1}"
            parameters.append(name)
            segments.append("{" + name + "}")
        else:
            segments.append(segment)
    return ("/" + "/".join(segments)) if segments else "/", parameters


def _tool_name(method: str, template: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "_", f"{method.lower()}_{template}".lower()).strip("_")
    return base or method.lower() or "request"


def environment_manifest(
    record: dict[str, Any],
    *,
    include_query_names: bool = True,
    offset: int = 0,
    limit: int = 64,
) -> dict[str, Any]:
    result = record.get("normalized_result") or {}
    requests = result.get("requests") or []
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    body_unknown = False
    for ordinal, request in enumerate(requests):
        if not isinstance(request, dict):
            continue
        method = str(request.get("method") or "GET")
        url = str(request.get("url") or "")
        parsed = urlsplit(url)
        template, path_parameters = _path_template(parsed.path)
        query_names = (
            sorted(parse_qs(parsed.query, keep_blank_values=True)) if include_query_names else []
        )
        key = (method, template)
        group = groups.setdefault(
            key,
            {
                "method": method,
                "path_template": template,
                "parameters": {},
                "statuses": set(),
                "content_types": set(),
                "ordinals": [],
                "host": parsed.hostname,
            },
        )
        for name in path_parameters:
            group["parameters"][name] = "path"
        for name in query_names:
            group["parameters"][name] = "query"
        if request.get("status") is not None:
            group["statuses"].add(request.get("status"))
        if request.get("mime_type"):
            group["content_types"].add(str(request.get("mime_type")))
        group["ordinals"].append(ordinal)
        if method.upper() in ("POST", "PUT", "PATCH"):
            body_unknown = True
    tools = []
    used: dict[str, int] = {}
    for (method, template), group in sorted(groups.items()):
        name = _tool_name(method, template)
        if name in used:
            used[name] += 1
            name = f"{name}_{used[name]}"
        else:
            used[name] = 1
        tools.append(
            {
                "name": name,
                "method": method,
                "path_template": template,
                "host": group["host"],
                "parameters": [
                    {"name": parameter, "location": location}
                    for parameter, location in sorted(group["parameters"].items())
                ],
                "statuses": sorted(group["statuses"], key=lambda value: str(value)),
                "content_types": sorted(group["content_types"]),
                "body_shape": None,
                "record_ordinals": group["ordinals"][:200],
            }
        )
    limitations = [
        "Path templates, parameter names and tool names are inferences.",
        "No header, cookie, query value or body value is copied into the view.",
    ]
    unknowns = []
    if body_unknown:
        unknowns.append(
            "POST/PUT/PATCH body shapes are unknown because request bodies were not retained."
        )
    total = len(tools)
    offset = max(0, offset)
    limit = min(1000, max(1, limit))
    start = min(offset, total)
    page = tools[start : start + limit]
    return {
        "kind": "environment-manifest",
        "parent_evidence_id": record.get("evidence_id"),
        "tool_count": total,
        "offset": start,
        "next_offset": start + len(page) if start + len(page) < total else None,
        "tools": page,
        "limitations": limitations,
        "unknowns": unknowns,
    }


def javascript_facts(
    record: dict[str, Any],
    *,
    paths: list[str] | None = None,
    property_keys: list[str] | None = None,
    offset: int = 0,
    limit: int = 64,
) -> dict[str, Any]:
    result = record.get("normalized_result") or {}
    modules = result.get("modules") or {}
    selected = []
    for path in sorted(modules):
        if paths and path not in paths:
            continue
        module = modules[path] if isinstance(modules[path], dict) else {}
        facts = {
            "path": path,
            "size": module.get("size"),
            "imports": module.get("imports") or [],
            "import_count": len(module.get("imports") or []),
        }
        if property_keys:
            facts = {"path": path, **{key: facts.get(key) for key in property_keys}}
        selected.append(facts)
    start = min(max(0, offset), len(selected))
    page = selected[start : start + max(0, limit)]
    return {
        "kind": "javascript-facts",
        "parent_evidence_id": record.get("evidence_id"),
        "total": len(selected),
        "offset": start,
        "next_offset": start + len(page) if start + len(page) < len(selected) else None,
        "rows": page,
        "limitations": ["Path and property matching uses exact retained strings."],
    }


def javascript_view(
    record: dict[str, Any], *, paths: list[str] | None = None, offset: int = 0, limit: int = 64
) -> dict[str, Any]:
    result = record.get("normalized_result") or {}
    modules = result.get("modules") or {}
    edges = result.get("edges") or []
    if paths:
        modules = {path: value for path, value in modules.items() if path in paths}
        edges = [edge for edge in edges if edge.get("from") in paths or edge.get("to") in paths]
    ordered = sorted(edges, key=lambda edge: (str(edge.get("from")), str(edge.get("to"))))
    start = min(max(0, offset), len(ordered))
    page = ordered[start : start + max(0, limit)]
    return {
        "kind": "javascript",
        "parent_evidence_id": record.get("evidence_id"),
        "module_count": len(modules),
        "modules": sorted(modules),
        "edge_total": len(ordered),
        "offset": start,
        "next_offset": start + len(page) if start + len(page) < len(ordered) else None,
        "edges": page,
        "limitations": ["Graph edges are specifier strings, not resolved module identities."],
    }


_VIEWS = {
    "summary",
    "record",
    "page",
    "environment-manifest",
    "javascript-facts",
    "javascript",
    "managed",
    "managed-members",
    "desktop-application",
}


def _guard_view(
    value: dict[str, Any],
    *,
    view: str,
    source: str | Path,
    budget_bytes: int,
    summary: dict[str, Any] | None = None,
    evidence_id: str | None = None,
) -> dict[str, Any]:
    size = len(json.dumps(value, ensure_ascii=False, default=str).encode("utf-8"))
    if size <= budget_bytes:
        return value
    return {
        "kind": "truncated",
        "truncated": True,
        "view": view,
        "source": str(source),
        "budget_bytes": budget_bytes,
        "result_bytes": size,
        "evidence_reference": (
            {"kind": "retained-evidence", "evidence_id": evidence_id} if evidence_id else None
        ),
        "summary": summary or {"keys": sorted(value.keys()) if isinstance(value, dict) else None},
        "hint": "Use view=page with offset/limit, or the source file for the complete record.",
    }


_MANAGED_COLLECTIONS: dict[str, tuple[str, ...]] = {
    "managed": ("references", "resources", "attributes"),
    "managed-members": (
        "types",
        "exported_types",
        "fields",
        "methods",
        "member_refs",
        "call_edges",
        "field_accesses",
        "field_initializers",
        "user_strings",
    ),
    "desktop-application": ("files", "candidates", "components", "next_probes"),
}


def _managed_view(
    record: dict[str, Any],
    view: str,
    collection: str | None,
    offset: int,
    limit: int,
) -> Result[dict[str, Any], AnalysisError]:
    normalized = record.get("normalized_result")
    if not isinstance(normalized, dict):
        return err(
            AnalysisInputError(
                operation="inspect_analysis_view",
                message="Managed parent Evidence has no normalized_result object.",
            )
        )
    allowed = _MANAGED_COLLECTIONS[view]
    if collection is None:
        return err(
            AnalysisInputError(
                operation="inspect_analysis_view",
                message=f"{view} requires collection one of {sorted(allowed)}.",
            )
        )
    if collection not in allowed:
        return err(
            AnalysisInputError(
                operation="inspect_analysis_view",
                message=f"Unknown {view} collection {collection!r}; choose one of {sorted(allowed)}.",
            )
        )
    rows = normalized.get(collection)
    if collection == "user_strings":
        user_strings = normalized.get("user_strings")
        rows = user_strings.get("literals") if isinstance(user_strings, dict) else None
        if rows is None:
            return err(
                AnalysisInputError(
                    operation="inspect_analysis_view",
                    message="The parent Evidence did not examine user strings.",
                )
            )
    if rows is None:
        return err(
            AnalysisInputError(
                operation="inspect_analysis_view",
                message=f"The parent Evidence did not examine {collection}.",
            )
        )
    if not isinstance(rows, list):
        return err(
            AnalysisInputError(
                operation="inspect_analysis_view",
                message=f"Managed collection {collection!r} is not a row list.",
            )
        )
    offset = max(0, offset)
    limit = min(10_000, max(1, limit))
    start = min(offset, len(rows))
    page = rows[start : start + limit]
    if collection == "types":
        page = [
            {key: value for key, value in row.items() if key not in ("methods", "fields")}
            if isinstance(row, dict)
            else row
            for row in page
        ]
    return ok(
        {
            "kind": view,
            "parent_evidence_id": record.get("evidence_id"),
            "collection": collection,
            "offset": start,
            "limit": limit,
            "total": len(rows),
            "next_offset": start + len(page) if start + len(page) < len(rows) else None,
            "rows": page,
            "selection": normalized.get("selection"),
            "source_coverage": normalized.get("coverage"),
            "source_metadata_status": (normalized.get("metadata") or {}).get("status"),
            "source_signature_resolution": normalized.get("signature_resolution"),
            "source_nesting_read": normalized.get("nesting_read"),
        }
    )


def load_view(
    source: str | Path,
    view: str = "summary",
    *,
    offset: int = 0,
    limit: int = 64,
    paths: list[str] | None = None,
    property_keys: list[str] | None = None,
    evidence_id: str | None = None,
    collection: str | None = None,
    budget_bytes: int = 512 * 1024,
) -> Result[dict[str, Any], AnalysisError]:
    path = Path(source)
    if not path.is_file():
        return err(
            AnalysisInputError(operation="inspect_analysis_view", message=f"Not found: {source}")
        )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as cause:
        return err(AnalysisInputError(operation="inspect_analysis_view", message=str(cause)))
    if view not in _VIEWS:
        return err(
            AnalysisInputError(
                operation="inspect_analysis_view",
                message=f"Unknown view {view!r}; choose one of {sorted(_VIEWS)}.",
            )
        )
    if view == "summary":
        if "records" in payload:
            return ok(summarize_bundle(payload))
        if "evidence_id" in payload:
            return ok(summarize_record(payload))
        return err(
            AnalysisInputError(
                operation="inspect_analysis_view",
                message="Source is neither an Evidence record nor a bundle",
            )
        )
    if view == "page":
        if "records" not in payload:
            return err(
                AnalysisInputError(
                    operation="inspect_analysis_view",
                    message="view=page requires an Evidence bundle (or use view=record).",
                )
            )
        return ok(
            _guard_view(
                page_bundle(payload, offset, limit),
                view=view,
                source=path,
                budget_bytes=budget_bytes,
                summary=summarize_bundle(payload),
            )
        )
    if view in ("managed", "managed-members", "desktop-application"):
        record = _select_record(payload, view, evidence_id)
        if record is None:
            return err(
                AnalysisInputError(
                    operation="inspect_analysis_view",
                    message=f"No retained {view} parent Evidence was found in the source.",
                )
            )
        projected = _managed_view(record, view, collection, offset, limit)
        if not projected.ok:
            return projected
        return ok(
            _guard_view(
                projected.value,
                view=view,
                source=path,
                budget_bytes=budget_bytes,
                summary=summarize_record(record),
                evidence_id=record.get("evidence_id"),
            )
        )
    if view in ("environment-manifest", "javascript-facts", "javascript"):
        record = _select_record(payload, view, evidence_id)
        if record is None:
            return err(
                AnalysisInputError(
                    operation="inspect_analysis_view",
                    message=f"No retained {view} parent Evidence was found in the source.",
                )
            )
        if view == "environment-manifest":
            result = environment_manifest(record, offset=offset, limit=limit)
            summary = {
                "parent_evidence_id": result["parent_evidence_id"],
                "tool_count": result["tool_count"],
            }
        elif view == "javascript-facts":
            result = javascript_facts(
                record,
                paths=paths,
                property_keys=property_keys,
                offset=offset,
                limit=limit,
            )
            summary = {
                "parent_evidence_id": result["parent_evidence_id"],
                "total": result["total"],
            }
        else:
            result = javascript_view(record, paths=paths, offset=offset, limit=limit)
            summary = {
                "parent_evidence_id": result["parent_evidence_id"],
                "edge_total": result["edge_total"],
            }
        return ok(
            _guard_view(
                result,
                view=view,
                source=path,
                budget_bytes=budget_bytes,
                summary=summary,
                evidence_id=record.get("evidence_id"),
            )
        )
    # view == "record"
    if "records" in payload:
        if not evidence_id:
            return err(
                AnalysisInputError(
                    operation="inspect_analysis_view",
                    message="view=record on a bundle requires evidence_id; use view=page for a list.",
                )
            )
        record = _select_record(payload, "record", evidence_id)
        if record is None:
            return err(
                AnalysisInputError(
                    operation="inspect_analysis_view",
                    message=f"Evidence {evidence_id} was not found in the bundle.",
                )
            )
    elif "evidence_id" in payload:
        record = payload
    else:
        return err(
            AnalysisInputError(
                operation="inspect_analysis_view",
                message="Source is neither an Evidence record nor a bundle",
            )
        )
    return ok(
        _guard_view(
            record,
            view=view,
            source=path,
            budget_bytes=budget_bytes,
            summary=summarize_record(record),
            evidence_id=record.get("evidence_id"),
        )
    )


__all__ = [
    "environment_manifest",
    "javascript_facts",
    "javascript_view",
    "load_view",
    "page_bundle",
    "summarize_bundle",
    "summarize_record",
]
