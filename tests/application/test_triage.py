from __future__ import annotations

from pathlib import Path

from rea_mcp.application.triage import triage_target
from rea_mcp.composition.factories import create_binary_session
from rea_mcp.config.settings import AppConfig


def test_triage_native_returns_compact_evidence(elf_file: Path) -> None:
    session = create_binary_session(AppConfig())
    result = triage_target(session, str(elf_file), question="what is this?")
    assert result.ok
    data = result.value
    assert data["kind"] == "triage"
    assert data["target"]["format"] == "elf"
    assert data["probe_count"] >= 1
    assert data["evidence_ids"]
    assert data["question"] == "what is this?"
    assert all(probe["evidence_id"] for probe in data["probes"])
    assert any(probe["operation"] == "inspect_binary_layout" for probe in data["probes"])
    assert data["elapsed_ms"] >= 0


def test_triage_without_target_or_path_is_an_error() -> None:
    session = create_binary_session(AppConfig())
    result = triage_target(session)
    assert not result.ok


def test_triage_apk_and_javascript_directory(apk_file: Path, js_dir: Path) -> None:
    apk_session = create_binary_session(AppConfig())
    apk = triage_target(apk_session, str(apk_file))
    assert apk.ok
    assert apk.value["target"]["format"] == "apk"
    operations = {probe["operation"] for probe in apk.value["probes"]}
    assert "inspect_android_package" in operations

    js_session = create_binary_session(AppConfig())
    js = triage_target(js_session, str(js_dir))
    assert js.ok
    assert js.value["target"]["format"] in ("directory", "asar")
    operations = {probe["operation"] for probe in js.value["probes"]}
    assert "analyze_javascript_application" in operations
