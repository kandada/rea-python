"""Projection of saved Evidence into small summaries (token-first delivery)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

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


def load_view(
    source: str | Path,
    view: str = "summary",
    *,
    offset: int = 0,
    limit: int = 64,
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

    if "records" in payload:
        if view == "page":
            return ok(page_bundle(payload, offset, limit))
        return ok(summarize_bundle(payload) if view == "summary" else payload)
    if "evidence_id" in payload:
        return ok(summarize_record(payload) if view == "summary" else payload)
    return err(
        AnalysisInputError(
            operation="inspect_analysis_view",
            message="Source is neither an Evidence record nor a bundle",
        )
    )


__all__ = ["load_view", "page_bundle", "summarize_bundle", "summarize_record"]
