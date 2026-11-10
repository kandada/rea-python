from __future__ import annotations

import sys
from pathlib import Path

from rea_mcp.application.craft.builders import (
    _prompt_for,
    detect_builders,
    resolve_builder,
    run_builder,
)
from rea_mcp.application.project_store import create_project


def _store(tmp_path: Path):
    created = create_project(tmp_path / "project", name="Demo", request="build it")
    assert created.ok
    return created.value


def test_detect_and_resolve_custom_builder(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REA_CRAFT_BUILDER_COMMAND", f"{sys.executable} -c pass {{prompt}}")
    assert detect_builders() == ["custom"]
    result = resolve_builder("custom")
    assert result.ok
    assert result.value.name == "custom"
    assert result.value.command[-1] == "{prompt}"


def test_resolve_unknown_builder_program(tmp_path: Path) -> None:
    result = resolve_builder(f"{sys.executable} -c pass {{prompt}}")
    assert result.ok
    assert result.value.name == Path(sys.executable).name
    assert result.value.command[-1] == "{prompt}"


def test_resolve_builder_rejects_bad_shell_syntax() -> None:
    result = resolve_builder("'unterminated")
    assert not result.ok
    assert "builder" in result.error.message


def test_resolve_missing_known_builder(monkeypatch) -> None:
    import rea_mcp.application.craft.builders as builders

    monkeypatch.setattr(builders.shutil, "which", lambda name: None)
    result = resolve_builder("codex")
    assert not result.ok
    assert "not on PATH" in result.error.message


def test_run_builder_success_and_failure(tmp_path: Path, monkeypatch) -> None:
    store = _store(tmp_path)
    script = tmp_path / "builder.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    monkeypatch.setenv("REA_CRAFT_BUILDER_COMMAND", f"{sys.executable} {script} {{prompt}}")
    result = run_builder(store, round_number=2)
    assert result.ok, result
    assert result.value["exit_code"] == 0
    assert (store.root / "builds/round-0002/prompt.md").is_file()
    assert (store.root / "builds/round-0002/builder.json").is_file()
    assert store.manifest.usage.turns == 1

    failing = tmp_path / "fail.py"
    failing.write_text("raise SystemExit(3)\n", encoding="utf-8")
    monkeypatch.setenv("REA_CRAFT_BUILDER_COMMAND", f"{sys.executable} {failing} {{prompt}}")
    result = run_builder(store, round_number=3)
    assert not result.ok
    assert "exited 3" in result.error.message


def test_run_builder_timeout(tmp_path: Path, monkeypatch) -> None:
    store = _store(tmp_path)
    script = tmp_path / "slow.py"
    script.write_text("import time; time.sleep(5)\n", encoding="utf-8")
    monkeypatch.setenv("REA_CRAFT_BUILDER_COMMAND", f"{sys.executable} {script} {{prompt}}")
    result = run_builder(store, timeout=0.05)
    assert not result.ok
    assert "timed out" in result.error.message.lower()


def test_prompt_contains_engine_recipes(tmp_path: Path) -> None:
    store = _store(tmp_path)
    for stack, expected in (
        ("unity", "CraftBuild.cs"),
        ("unreal", "RunUAT"),
        ("godot", "self-test.json"),
    ):
        store.manifest.stack = stack
        prompt = _prompt_for(store, ["load failed"])
        assert expected in prompt
        assert "Previous check failures" in prompt
