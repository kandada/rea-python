import json
from pathlib import Path

from rea_mcp.application.workflows import (
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
    bundle = get_evidence_bundle(session)
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
