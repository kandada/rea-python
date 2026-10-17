import json
from pathlib import Path

from rea_mcp.application.analysis_view import load_view
from rea_mcp.composition.factories import create_binary_session
from rea_mcp.config.settings import AppConfig


def _bundle_path(tmp_path: Path, elf_file: Path) -> Path:
    session = create_binary_session(AppConfig())
    session.open(str(elf_file))
    session.execute("inspect_binary_layout")
    bundle = session.export_bundle()
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    return path


def test_summarize_bundle(tmp_path: Path, elf_file: Path) -> None:
    view = load_view(_bundle_path(tmp_path, elf_file), "summary")
    assert view.ok
    assert view.value["kind"] == "bundle"
    assert view.value["record_count"] == 1
    assert view.value["operations"] == {"inspect_binary_layout": 1}


def test_record_source(tmp_path: Path, elf_file: Path) -> None:
    bundle_path = _bundle_path(tmp_path, elf_file)
    bundle = json.loads(bundle_path.read_text())
    record_path = tmp_path / "record.json"
    record_path.write_text(json.dumps(bundle["records"][0]), encoding="utf-8")
    view = load_view(record_path, "summary")
    assert view.ok
    assert view.value["kind"] == "record"
    assert view.value["operation"] == "inspect_binary_layout"


def test_missing_source_is_error(tmp_path: Path) -> None:
    assert not load_view(tmp_path / "missing.json").ok
