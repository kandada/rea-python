"""Compare an environment's replay answers with probe capture exchanges."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs

from ...domain.environment_state_rules import canonical_json
from .source import EnvironmentSource, RecordedExchange, replayed_body


@dataclass
class ProbeComparison:
    ordinal: int
    path: str
    status: str
    differences: list[str]
    environment_record: int | None = None


def _query_map(query: str | None) -> dict[str, list[str]]:
    return parse_qs((query or "").lstrip("?"), keep_blank_values=True)


def _select(source: EnvironmentSource, probe: RecordedExchange) -> list[RecordedExchange]:
    return [
        exchange
        for exchange in source.exchanges.values()
        if exchange.path == probe.path and _query_map(exchange.query) == _query_map(probe.query)
    ]


def _body_equal(left: dict[str, Any], right: dict[str, Any]) -> bool:
    if left.get("kind") != right.get("kind"):
        return False
    if left.get("kind") == "json":
        try:
            return canonical_json(left.get("value")) == canonical_json(right.get("value"))
        except (TypeError, ValueError):
            return False
    return left.get("text") == right.get("text") and left.get("encoded") == right.get("encoded")


def compare_environment(
    source: EnvironmentSource, probes: EnvironmentSource | list[RecordedExchange]
) -> dict[str, Any]:
    if isinstance(probes, EnvironmentSource):
        records = list(probes.exchanges.values())
        probe_evidence = probes.evidence_id
    else:
        records = list(probes)
        probe_evidence = None
    rows: list[ProbeComparison] = []
    changed = 0
    unknown = 0
    for probe in sorted(records, key=lambda item: item.ordinal):
        candidates = _select(source, probe)
        if not candidates:
            unknown += 1
            rows.append(
                ProbeComparison(
                    probe.ordinal, probe.path, "unknown", ["no matching recorded exchange"]
                )
            )
            continue
        if len(candidates) > 1:
            unknown += 1
            rows.append(
                ProbeComparison(
                    probe.ordinal, probe.path, "unknown", ["ambiguous recorded exchanges"]
                )
            )
            continue
        recorded = candidates[0]
        differences = []
        if recorded.status != probe.status:
            differences.append(f"status {recorded.status!r} != {probe.status!r}")
        if (recorded.content_type or "") != (probe.content_type or ""):
            differences.append("content-type differs")
        if not _body_equal(replayed_body(recorded), replayed_body(probe)):
            differences.append("body differs")
        if differences:
            changed += 1
            rows.append(
                ProbeComparison(probe.ordinal, probe.path, "changed", differences, recorded.ordinal)
            )
        else:
            rows.append(
                ProbeComparison(probe.ordinal, probe.path, "unchanged", [], recorded.ordinal)
            )
    status = "changed" if changed else "unknown" if unknown else "unchanged"
    coverage = {
        "probe_count": len(rows),
        "matched": sum(1 for row in rows if row.environment_record is not None),
        "unchanged": len(rows) - changed - unknown,
        "changed": changed,
        "unknown": unknown,
        "matched_paths": sorted({row.path for row in rows if row.environment_record is not None}),
        "unknown_paths": sorted({row.path for row in rows if row.environment_record is None}),
        "state": "partial" if unknown else "complete",
    }
    return {
        "status": status,
        "probe_count": len(rows),
        "changed_count": changed,
        "unknown_count": unknown,
        "unchanged_count": len(rows) - changed - unknown,
        "probes": [row.__dict__ for row in rows],
        "environment_evidence_id": source.evidence_id,
        "probe_evidence_id": probe_evidence,
        "coverage": coverage,
        "limitations": [
            "Comparison uses recorded path/query/status/content-type/body; runtime behavior and unrecorded paths remain unknown.",
        ],
    }


__all__ = ["ProbeComparison", "compare_environment"]
