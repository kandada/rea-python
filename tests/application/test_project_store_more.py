from __future__ import annotations

from pathlib import Path

from rea_mcp.application.project_store import ProjectStore, create_project
from rea_mcp.domain.analysis_profile import ProviderIdentity
from rea_mcp.domain.evidence import EvidenceObservation, create_evidence
from rea_mcp.domain.project import ProjectUsage


def test_project_store_evidence_memory_and_usage(tmp_path: Path) -> None:
    created = create_project(tmp_path / "project", name="demo", request="x")
    assert created.ok
    store = created.value
    evidence = create_evidence(
        None,
        ProviderIdentity(id="test", name="Test", version="1"),
        EvidenceObservation("inspect", {"a": 1}),
    )
    path = store.add_evidence(evidence)
    assert path.is_file()
    assert store.evidence_ids() == [evidence.evidence_id]
    assert store.get_evidence(evidence.evidence_id) is not None
    store.add_unknown({"unknown_id": "u1", "question": "q", "status": "open"})
    store.add_finding({"finding_id": "f1", "claim": "c"})
    store.add_hypothesis({"hypothesis_id": "h1", "claim": "c"})
    store.journal({"event": "test"})
    store.add_usage(ProjectUsage(turns=2, tokens=10, seconds=1.5))
    assert store.list_unknowns()[0]["unknown_id"] == "u1"
    assert store.list_findings()[0]["finding_id"] == "f1"
    assert "test" in (store.read_text("investigation/journal.jsonl") or "")
    assert store.manifest.usage.tokens == 10
    assert store.summary()["evidence_count"] == 1
    assert store.next_round() == 1
    assert store.round_dir(7).name == "round-0007"


def test_project_store_approval_and_inbox_edges(tmp_path: Path) -> None:
    created = create_project(tmp_path / "p", name="p", request="x")
    assert created.ok
    store = created.value
    store.set_approval("commands", "refuse")
    store.set_approval("commands", "invalid")
    store.set_approval("unknown", "allow")
    assert store.manifest.approvals == {"commands": "refuse"}
    approval = store.ask_approval("publish", "push")
    assert store.inbox()[0]["id"] == approval["id"]
    assert not store.answer("missing", "x").ok
    assert store.answer(approval["id"], "allow").ok
    assert store.inbox() == []
    loaded = ProjectStore.open(tmp_path / "p")
    assert loaded.ok
    assert loaded.value.manifest.approvals["commands"] == "refuse"


def test_project_finish_pin_and_duplicate(tmp_path: Path) -> None:
    created = create_project(tmp_path / "base", name="Base", request="x")
    assert created.ok
    store = created.value
    store.app_dir.mkdir(parents=True, exist_ok=True)
    (store.app_dir / "index.html").write_text("hello", encoding="utf-8")
    finished = store.finish("accepted")
    assert finished["status"] == "ready"
    pin = store.pin("first")
    assert (Path(pin["path"]) / "app/index.html").read_text(encoding="utf-8") == "hello"
    assert store.list_pins()[0]["id"] == "first"
    assert store.delete_pin("first") is True
    assert store.list_pins() == []
    duplicated = store.duplicate(tmp_path / "copy", "Copy")
    assert Path(duplicated["path"]).is_dir()
    loaded = ProjectStore.open(tmp_path / "copy")
    assert loaded.ok
    assert loaded.value.manifest.name == "Copy"
    assert loaded.value.manifest.project_id != store.manifest.project_id


def test_project_pin_and_duplicate_errors(tmp_path: Path) -> None:
    import pytest

    created = create_project(tmp_path / "base", name="Base", request="x")
    assert created.ok
    store = created.value
    store.app_dir.mkdir(parents=True, exist_ok=True)
    (store.app_dir / "index.html").write_text("x", encoding="utf-8")
    store.pin("same")
    with pytest.raises(FileExistsError):
        store.pin("same")
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "keep").write_text("x", encoding="utf-8")
    with pytest.raises(FileExistsError):
        store.duplicate(occupied)


def test_analysis_cache_reuses_evidence_across_sessions(tmp_path: Path, monkeypatch) -> None:
    from rea_mcp.composition.factories import create_binary_session
    from rea_mcp.config.settings import AppConfig

    monkeypatch.setenv("REA_ANALYSIS_CACHE_DIR", str(tmp_path / "cache"))
    target = tmp_path / "sample.elf"
    from tests.conftest import build_elf

    target.write_bytes(build_elf({".text": b"\x90" * 16}))
    first = create_binary_session(AppConfig())
    assert first.open(str(target)).ok
    first_result = first.execute("inspect_binary_layout")
    assert first_result.ok
    cache_files = list((tmp_path / "cache").glob("*.json"))
    assert cache_files
    second = create_binary_session(AppConfig())
    assert second.open(str(target)).ok
    result = second.execute("inspect_binary_layout")
    assert result.ok
    assert result.value.evidence_id == first_result.value.evidence_id


def test_project_lock_survives_missing_fcntl(tmp_path: Path, monkeypatch) -> None:
    import importlib

    from rea_mcp.application.project_store import _project_lock

    real_import = importlib.import_module

    def fake_import(name: str, package: str | None = None):
        if name == "fcntl":
            raise ModuleNotFoundError("No module named 'fcntl'")
        return real_import(name, package)

    monkeypatch.setattr(importlib, "import_module", fake_import)
    root = tmp_path / "lock"
    root.mkdir()
    with _project_lock(root):
        assert (root / ".rea-project.lock").is_file()
