"""End-to-end CLI tests: run ``python -m rea_mcp`` as a real subprocess."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.e2e.harness import REPO_ROOT, cli_json, run_cli

pytestmark = pytest.mark.acceptance


def test_help_lists_commands() -> None:
    proc = run_cli(["--help"])
    assert proc.returncode == 0
    assert "inspect-binary-layout" in proc.stdout
    assert "doctor" in proc.stdout


def test_inspect_binary_layout_elf(elf_file: Path) -> None:
    payload = cli_json(["inspect-binary-layout", str(elf_file)])
    assert payload["evidence_id"].startswith("ev_")
    assert payload["normalized_result"]["format"] == "elf"
    assert payload["confidence"] == "observed"


def test_inspect_binary_layout_pe(pe_file: Path) -> None:
    payload = cli_json(["inspect-binary-layout", str(pe_file)])
    assert payload["normalized_result"]["format"] == "pe"


def test_inspect_go_binary(go_file: Path) -> None:
    payload = cli_json(["inspect-go-binary", str(go_file)])
    assert payload["normalized_result"]["is_go"] is True


def test_inspect_rust_binary(rust_file: Path) -> None:
    payload = cli_json(["inspect-rust-binary", str(rust_file)])
    assert payload["normalized_result"]["has_dependency_metadata"] is True


def test_inspect_managed_artifact(pe_clr_file: Path) -> None:
    payload = cli_json(["inspect-managed-artifact", str(pe_clr_file)])
    assert payload["normalized_result"]["is_managed"] is True


def test_inspect_sqlite_database(sqlite_file: Path) -> None:
    payload = cli_json(["inspect-sqlite-database", str(sqlite_file), "--table", "users"])
    assert payload["normalized_result"]["rows"]


def test_inspect_artifact(zip_file: Path) -> None:
    payload = cli_json(["inspect-artifact", str(zip_file)])
    assert payload["normalized_result"]["entry_count"] == 2


def test_inspect_android_package(apk_file: Path) -> None:
    payload = cli_json(["inspect-android-package", str(apk_file)])
    assert payload["normalized_result"]["dex_files"] == ["classes.dex"]


def test_identify_flutter_build(flutter_apk_file: Path) -> None:
    payload = cli_json(["identify-flutter-build", str(flutter_apk_file)])
    assert payload["normalized_result"]["is_flutter"] is True


def test_inspect_wasm_artifact(wasm_file: Path) -> None:
    payload = cli_json(["inspect-wasm-artifact", str(wasm_file)])
    assert payload["normalized_result"]["valid"] is True


def test_inspect_plist(plist_file: Path) -> None:
    payload = cli_json(["inspect-plist", str(plist_file)])
    assert payload["normalized_result"]["plist_format"] == "xml"


def test_import_reference_source(source_dir: Path) -> None:
    payload = cli_json(["import-reference-source", str(source_dir)])
    assert payload["normalized_result"]["file_count"] >= 2


def test_inspect_managed_members(pe_clr_file: Path) -> None:
    payload = cli_json(["inspect-managed-members", str(pe_clr_file)])
    assert payload["normalized_result"]["type_count"] == 1
    assert payload["normalized_result"]["types"][0]["full_name"] == "MyNamespace.MyType"


def test_inspect_network_capture(har_file: Path) -> None:
    payload = cli_json(["inspect-network-capture", str(har_file)])
    assert payload["normalized_result"]["entry_count"] == 2


def test_inspect_harmony_package(hap_file: Path) -> None:
    payload = cli_json(["inspect-harmony-package", str(hap_file)])
    assert payload["normalized_result"]["bundle_name"] == "com.example.app"


def test_analyze_javascript_application(js_dir: Path) -> None:
    payload = cli_json(["analyze-javascript-application", str(js_dir)])
    assert payload["normalized_result"]["module_count"] == 3


def test_inspect_keyed_archive(keyed_archive_file: Path) -> None:
    payload = cli_json(["inspect-keyed-archive", str(keyed_archive_file)])
    assert payload["normalized_result"]["is_keyed_archive"] is True


def test_inspect_pe_resources(pe_resources_file: Path) -> None:
    payload = cli_json(["inspect-pe-resources", str(pe_resources_file)])
    assert payload["normalized_result"]["has_resources"] is True


def test_setup_and_update(tmp_path: Path) -> None:
    plan = cli_json(["setup"])
    assert "server" in plan
    destination = tmp_path / "mcp.json"
    written = cli_json(["setup", "--write", str(destination)])
    assert destination.is_file()
    assert written["written"] == str(destination)
    update = cli_json(["update"])
    assert update["current_version"]


def test_providers_and_capabilities() -> None:
    providers = cli_json(["providers"])
    ids = {entry["id"] for entry in providers["providers"]}
    assert {"binary-layout", "go", "rust", "sqlite", "wasm", "plist"} <= ids

    capabilities = cli_json(["capabilities"])
    assert "inspect_binary_layout" in capabilities["operations"]


def test_doctor() -> None:
    payload = cli_json(["doctor"])
    assert "healthy" in payload
    assert payload["provider_count"] >= 16


def test_capture_process() -> None:
    import sys

    payload = cli_json(["capture-process", "--", sys.executable, "-c", "print('e2e')"])
    assert payload["stdout"].strip() == "e2e"
    assert payload["exit_code"] == 0


def test_compare_command(tmp_path: Path, elf_file: Path) -> None:
    first = run_cli(["inspect-binary-layout", str(elf_file)])
    left = tmp_path / "left.json"
    right = tmp_path / "right.json"
    left.write_text(first.stdout, encoding="utf-8")
    right.write_text(first.stdout, encoding="utf-8")
    payload = cli_json(["compare", str(left), str(right)])
    assert payload["status"] == "unchanged"


def test_missing_target_exits_nonzero(tmp_path: Path) -> None:
    proc = run_cli(["inspect-binary-layout", str(tmp_path / "nope")])
    assert proc.returncode == 1
    error = json.loads(proc.stderr)
    assert error["error"]["code"] == "INVALID_INPUT"


def test_piped_output_is_compact(elf_file: Path) -> None:
    proc = run_cli(["inspect-binary-layout", str(elf_file)])
    # Piped output is compact JSON (no indentation/newlines beyond the record).
    assert proc.stdout.count("\n") == 1
    json.loads(proc.stdout)


def test_evidence_view_and_bundle_commands(tmp_path: Path, elf_file: Path) -> None:
    record = run_cli(["inspect-binary-layout", str(elf_file)]).stdout
    record_path = tmp_path / "record.json"
    record_path.write_text(record, encoding="utf-8")

    view = cli_json(["inspect-analysis-view", str(record_path)])
    assert view["kind"] == "record"

    # Build a bundle through the library and exercise the CLI bundle commands.
    import sys

    sys.path.insert(0, str(REPO_ROOT))
    from rea_mcp.composition.factories import create_binary_session
    from rea_mcp.config.settings import AppConfig

    session = create_binary_session(AppConfig())
    session.open(str(elf_file))
    session.execute("inspect_binary_layout")
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(session.export_bundle()), encoding="utf-8")

    imported = cli_json(["evidence-import", str(bundle_path)])
    assert imported["valid"] is True
    assert imported["record_count"] == 1


def test_analysis_view_page(tmp_path: Path, elf_file: Path) -> None:
    import sys

    sys.path.insert(0, str(REPO_ROOT))
    from rea_mcp.composition.factories import create_binary_session
    from rea_mcp.config.settings import AppConfig

    session = create_binary_session(AppConfig())
    session.open(str(elf_file))
    session.execute("inspect_binary_layout")
    session.execute("inspect_artifact")
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(session.export_bundle()), encoding="utf-8")

    page = cli_json(["inspect-analysis-view", str(bundle_path), "--view", "page", "--limit", "1"])
    assert page["kind"] == "page"
    assert page["total"] == 2
    assert page["next_offset"] == 1


def test_json_flag_accepted_after_subcommand(elf_file: Path) -> None:
    proc = run_cli(["inspect-binary-layout", str(elf_file), "--json"])
    assert proc.returncode == 0, proc.stderr
    json.loads(proc.stdout)


def test_json_flag_accepted_before_subcommand() -> None:
    proc = run_cli(["--json", "providers"])
    assert proc.returncode == 0, proc.stderr
    json.loads(proc.stdout)


def test_capture_process_keeps_json_after_separator() -> None:
    import sys

    proc = run_cli(["capture-process", "--", sys.executable, "-c", "print('--json')"])
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["stdout"].strip() == "--json"


def test_version_flag() -> None:
    from rea_mcp import __version__

    proc = run_cli(["--version"])
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == __version__
