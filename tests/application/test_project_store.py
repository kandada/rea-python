from __future__ import annotations

from pathlib import Path

from rea_mcp.application.project_store import ProjectStore, create_project
from rea_mcp.domain.check import CheckResult, Claim


def test_project_store_persists_manifest_checks_inbox_and_policy(tmp_path: Path) -> None:
    created = create_project(
        tmp_path / "demo",
        name="Demo",
        request="rebuild it",
        target=str(tmp_path),
        mode="clean_room",
    )
    assert created.ok
    store = created.value
    assert store.manifest.mode == "clean_room"
    store.write_text("investigation/brief.md", "# Brief")
    check = CheckResult(
        "build",
        1,
        True,
        "static",
        claims=[Claim("loads", True)],
        artifacts=["app/index.html"],
    )
    store.save_check(check)
    asked = store.ask("Which font?", options=["A", "B"])
    assert store.answer(asked["id"], "A").ok
    store.set_approval("commands", "refuse")
    store.journal({"event": "test"})

    loaded = ProjectStore.open(tmp_path / "demo")
    assert loaded.ok
    assert loaded.value.manifest.approvals["commands"] == "refuse"
    assert loaded.value.latest_checks()[0].check == "build"
    assert loaded.value.inbox() == []
    assert "test" in (loaded.value.read_text("investigation/journal.jsonl") or "")


def test_project_store_refuses_nonempty_destination(tmp_path: Path) -> None:
    root = tmp_path / "busy"
    root.mkdir()
    (root / "keep.txt").write_text("keep", encoding="utf-8")
    result = create_project(root, name="Demo", request="x")
    assert not result.ok
