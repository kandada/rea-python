from __future__ import annotations

from rea_mcp.application.environment.compare import compare_environment
from rea_mcp.application.environment.source import EnvironmentSource, RecordedExchange


def _source() -> EnvironmentSource:
    return EnvironmentSource(
        manifest={},
        manifest_evidence_id="ev_m",
        evidence_id="ev_c",
        capture_kind="web-network-capture",
        capture_sha256=None,
        exchanges={
            0: RecordedExchange(0, "/api/items/1", None, 200, "application/json", '{"id":1}'),
        },
    )


def test_compare_unchanged_and_changed() -> None:
    probe = EnvironmentSource(
        manifest={},
        manifest_evidence_id="ev_pm",
        evidence_id="ev_probe",
        capture_kind="web-network-capture",
        capture_sha256=None,
        exchanges={
            0: RecordedExchange(0, "/api/items/1", None, 200, "application/json", '{"id":1}')
        },
    )
    unchanged = compare_environment(_source(), probe)
    assert unchanged["status"] == "unchanged"
    probe.exchanges[0].body_text = '{"id":2}'
    changed = compare_environment(_source(), [probe.exchanges[0]])
    assert changed["status"] == "changed"
    assert changed["probes"][0]["differences"]


def test_compare_unknown() -> None:
    result = compare_environment(
        _source(), [RecordedExchange(0, "/missing", None, 200, None, None)]
    )
    assert result["status"] == "unknown"
