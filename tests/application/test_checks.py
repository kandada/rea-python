from __future__ import annotations

from pathlib import Path

from PIL import Image

from rea_mcp.application.checks.basic import build_project, visual_check
from rea_mcp.application.checks.runtime_ui import runtime_ui_check
from rea_mcp.application.project_store import create_project


def test_build_check_static_and_unknown(tmp_path: Path) -> None:
    static = tmp_path / "static"
    static.mkdir()
    (static / "index.html").write_text("<html></html>", encoding="utf-8")
    assert build_project(static).passed is True
    empty = tmp_path / "empty"
    empty.mkdir()
    result = build_project(empty)
    assert result.passed is False
    assert "no known project" in result.note


def test_build_check_unity_and_unreal_need_engines(tmp_path: Path, monkeypatch) -> None:
    import rea_mcp.application.checks.basic as checks

    monkeypatch.setattr(checks, "_unity", lambda: None)
    unity = tmp_path / "unity"
    (unity / "Assets").mkdir(parents=True)
    (unity / "ProjectSettings").mkdir()
    result = build_project(unity)
    assert not result.passed
    assert result.unknowns == ["Unity editor"]

    monkeypatch.setattr(checks, "_unreal", lambda: None)
    unreal = tmp_path / "unreal"
    unreal.mkdir()
    (unreal / "Demo.uproject").write_text("{}", encoding="utf-8")
    result = build_project(unreal)
    assert not result.passed
    assert result.unknowns == ["Unreal Engine"]


def test_visual_check_detects_color_difference_and_missing_shot(tmp_path: Path) -> None:
    original = tmp_path / "original.png"
    built = tmp_path / "built.png"
    Image.new("RGB", (200, 120), (250, 250, 250)).save(original)
    Image.new("RGB", (200, 120), (20, 20, 20)).save(built)

    def capture(shot: Path) -> dict:
        return {
            "widths": [1440],
            "screenshots": [str(shot)],
            "pages": {
                "1440": {
                    "scrollWidth": 1440,
                    "scrollHeight": 120,
                    "text": "hello",
                    "headings": [{"text": "Hello"}],
                    "colors": ["rgb(0,0,0)"],
                }
            },
        }

    changed = visual_check(capture(original), capture(built), round_number=1, good_enough=85)
    assert changed.passed is False
    assert changed.similarity is not None and changed.similarity < 50
    missing = capture(original)
    missing["screenshots"] = []
    result = visual_check(missing, capture(built), round_number=1, good_enough=85)
    assert result.passed is False
    assert result.unknowns


def test_runtime_ui_missing_manifest(tmp_path: Path) -> None:
    created = create_project(tmp_path / "app", name="app", request="x")
    assert created.ok
    result = runtime_ui_check(created.value, 1)
    assert result.passed is False
    assert result.unknowns == ["runtime manifest"]


def test_godot_build_if_vendor_engine_is_present(tmp_path: Path) -> None:
    import pytest

    from rea_mcp.application.checks.basic import _godot

    if _godot() is None:
        pytest.skip("Godot engine is not installed")
    app = tmp_path / "godot"
    app.mkdir()
    (app / "project.godot").write_text('[application]\nconfig/name="Demo"\n', encoding="utf-8")
    result = build_project(app)
    assert result.passed is True


def test_build_check_package_and_python_errors(tmp_path: Path) -> None:
    package = tmp_path / "package"
    package.mkdir()
    (package / "package.json").write_text("{bad", encoding="utf-8")
    assert build_project(package).passed is False
    no_script = tmp_path / "noscript"
    no_script.mkdir()
    (no_script / "package.json").write_text('{"name":"x"}', encoding="utf-8")
    assert build_project(no_script).passed is True
    python = tmp_path / "python"
    python.mkdir()
    (python / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    (python / "bad.py").write_text("def broken(:\n", encoding="utf-8")
    assert build_project(python).passed is False


def test_runtime_invalid_manifest(tmp_path: Path) -> None:
    from rea_mcp.application.checks.runtime import runtime_check

    created = create_project(tmp_path / "runtime-invalid", name="x", request="x")
    assert created.ok
    store = created.value
    store.app_dir.mkdir(parents=True, exist_ok=True)
    (store.app_dir / "runtime.json").write_text("{}", encoding="utf-8")
    result = runtime_check(store, 1)
    assert result.passed is False
    assert "command" in result.note
