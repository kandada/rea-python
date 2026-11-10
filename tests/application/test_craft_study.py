from __future__ import annotations

import json
from pathlib import Path

from rea_mcp.application.craft.study import _reference_files, detect_game_engine, study_project
from rea_mcp.application.project_store import create_project


def _store(tmp_path: Path, target: str | None, mode: str = "clean_room"):
    created = create_project(
        tmp_path / "project", name="Demo", request="x", target=target, mode=mode
    )
    assert created.ok
    return created.value


def test_study_local_clean_room(tmp_path: Path) -> None:
    target_file = tmp_path / "target.bin"
    target_file.write_bytes(b"x")
    store = _store(tmp_path, str(target_file))
    reference = store.root / "reference" / "notes" / "a.md"
    reference.parent.mkdir(parents=True)
    reference.write_text("hi", encoding="utf-8")
    result = study_project(store)
    assert result.ok, result
    capture = json.loads((store.capture_dir / "target.json").read_text(encoding="utf-8"))
    assert capture["clean_room"] is True
    assert (store.investigation_dir / "brief.md").is_file()
    assert _reference_files(store) == ["reference/notes/a.md"]
    assert store.manifest.status == "building"
    assert store.manifest.step == "build"


def test_study_missing_local_target_fails(tmp_path: Path) -> None:
    store = _store(tmp_path, str(tmp_path / "missing"))
    result = study_project(store)
    assert not result.ok
    assert "missing" in result.error.message
    assert store.manifest.status == "failed"


def test_study_environment_copies_files(tmp_path: Path) -> None:
    source = tmp_path / "env"
    source.mkdir()
    (source / "manifest.json").write_text("{}", encoding="utf-8")
    (source / "evidence.json").write_text("{}", encoding="utf-8")
    store = _store(tmp_path, str(source))
    result = study_project(store)
    assert result.ok, result
    assert (store.capture_dir / "environment/manifest.json").is_file()
    assert result.value["capture"]["kind"] == "environment"


def test_study_none_and_website_without_url(tmp_path: Path) -> None:
    store = _store(tmp_path, None)
    result = study_project(store)
    assert result.ok
    assert result.value["capture"]["kind"] == "none"

    website = _store(tmp_path / "web", None)
    website.manifest.target = {"kind": "website"}
    result = study_project(website)
    assert not result.ok
    assert "URL" in result.error.message
    assert website.manifest.status == "failed"


def test_detect_game_engines(tmp_path: Path) -> None:
    assert detect_game_engine(tmp_path) is None
    (tmp_path / "Game.uproject").write_text("{}", encoding="utf-8")
    assert detect_game_engine(tmp_path)["engine"] == "unreal"
    (tmp_path / "Game.uproject").unlink()
    (tmp_path / "UnityPlayer.dll").write_bytes(b"")
    assert detect_game_engine(tmp_path)["engine"] == "unity"
    (tmp_path / "UnityPlayer.dll").unlink()
    (tmp_path / "GameAssembly.dll").write_bytes(b"")
    assert detect_game_engine(tmp_path)["engine"] == "unity-il2cpp"


def test_detect_unity_by_directories(tmp_path: Path) -> None:
    (tmp_path / "Assets").mkdir()
    (tmp_path / "ProjectSettings").mkdir()
    assert detect_game_engine(tmp_path) == {
        "engine": "unity",
        "clue": "UnityPlayer.dll or Assets/ProjectSettings",
    }
