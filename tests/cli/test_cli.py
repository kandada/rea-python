import json
from pathlib import Path

from typer.testing import CliRunner

from rea_mcp.cli.app import app

runner = CliRunner()


def test_inspect_binary_layout(elf_file: Path) -> None:
    result = runner.invoke(app, ["inspect-binary-layout", str(elf_file)])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["evidence_id"].startswith("ev_")
    assert payload["normalized_result"]["format"] == "elf"


def test_providers_command() -> None:
    result = runner.invoke(app, ["providers"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert any(provider["id"] == "binary-layout" for provider in payload["providers"])


def test_capabilities_command() -> None:
    result = runner.invoke(app, ["capabilities"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert "inspect_go_binary" in payload["operations"]


def test_missing_target_fails(tmp_path: Path) -> None:
    result = runner.invoke(app, ["inspect-binary-layout", str(tmp_path / "nope")])
    assert result.exit_code == 1


def test_sqlite_command(sqlite_file: Path) -> None:
    result = runner.invoke(app, ["inspect-sqlite-database", str(sqlite_file), "--table", "users"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["normalized_result"]["rows"]


def test_analysis_view_command(tmp_path: Path, elf_file: Path) -> None:
    inspect = runner.invoke(app, ["inspect-binary-layout", str(elf_file)])
    record_path = tmp_path / "record.json"
    record_path.write_text(inspect.stdout, encoding="utf-8")
    view = runner.invoke(app, ["inspect-analysis-view", str(record_path)])
    assert view.exit_code == 0
    payload = json.loads(view.stdout)
    assert payload["kind"] == "record"


def test_doctor_command() -> None:
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert "healthy" in payload
    assert any(entry["id"] == "binary-layout" for entry in payload["providers"])


def test_capture_process_command() -> None:
    import sys

    result = runner.invoke(app, ["capture-process", "--", sys.executable, "-c", "print('hi')"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["stdout"].strip() == "hi"


def test_compare_command(tmp_path: Path, elf_file: Path) -> None:
    first = runner.invoke(app, ["inspect-binary-layout", str(elf_file)])
    left = tmp_path / "left.json"
    right = tmp_path / "right.json"
    left.write_text(first.stdout, encoding="utf-8")
    right.write_text(first.stdout, encoding="utf-8")
    result = runner.invoke(app, ["compare", str(left), str(right)])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "unchanged"


def test_import_reference_source_command(source_dir: Path) -> None:
    result = runner.invoke(app, ["import-reference-source", str(source_dir)])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["normalized_result"]["file_count"] >= 2


def test_inspect_plist_command(plist_file: Path) -> None:
    result = runner.invoke(app, ["inspect-plist", str(plist_file)])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["normalized_result"]["plist_format"] == "xml"
