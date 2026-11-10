from __future__ import annotations

import json
import subprocess
from pathlib import Path

from rea_mcp.application.checks import runtime_ui
from rea_mcp.application.project_store import create_project


class _FakeProcess:
    def __init__(self, pid: int = 1234) -> None:
        self.pid = pid
        self.returncode = 0
        self._polls = 0

    def poll(self) -> int | None:
        self._polls += 1
        return None if self._polls == 1 else 0

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        return 0


def _store(tmp_path: Path):
    created = create_project(tmp_path / "app", name="app", request="x")
    assert created.ok
    store = created.value
    store.app_dir.mkdir(parents=True, exist_ok=True)
    return store


def _manifest(store, payload) -> None:
    (store.app_dir / "runtime.json").write_text(json.dumps(payload), encoding="utf-8")


def test_runtime_ui_invalid_json(tmp_path: Path) -> None:
    store = _store(tmp_path)
    (store.app_dir / "runtime.json").write_text("{bad", encoding="utf-8")
    result = runtime_ui.runtime_ui_check(store, 2)
    assert not result.passed
    assert "unreadable" in result.note
    assert result.round == 2


def test_runtime_ui_rejects_missing_command(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _manifest(store, {"window_title": "Demo"})
    result = runtime_ui.runtime_ui_check(store, 1)
    assert not result.passed
    assert "command" in result.note
    _manifest(store, {"command": ["ok", 1]})
    assert "command" in runtime_ui.runtime_ui_check(store, 1).note


def test_runtime_ui_success_claims(tmp_path: Path, monkeypatch) -> None:
    store = _store(tmp_path)
    _manifest(
        store,
        {
            "command": ["fake-app"],
            "window_title": "Demo",
            "ui_labels": ["Start", "Settings"],
        },
    )
    monkeypatch.setattr(runtime_ui.subprocess, "Popen", lambda *a, **k: _FakeProcess())
    monkeypatch.setattr(runtime_ui.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(runtime_ui, "_window_titles", lambda pid: (["Demo - App"], None))
    monkeypatch.setattr(runtime_ui, "_ui_labels", lambda pid: (["Start", "Settings"], None))
    result = runtime_ui.runtime_ui_check(store, 3)
    assert result.passed
    assert result.round == 3
    assert [claim.passed for claim in result.claims] == [True, True, True, True]


def test_runtime_ui_reports_title_and_label_mismatch(tmp_path: Path, monkeypatch) -> None:
    store = _store(tmp_path)
    _manifest(
        store,
        {"command": ["fake-app"], "window_title": "Demo", "ui_labels": ["Start"]},
    )
    monkeypatch.setattr(runtime_ui.subprocess, "Popen", lambda *a, **k: _FakeProcess())
    monkeypatch.setattr(runtime_ui.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(runtime_ui, "_window_titles", lambda pid: (["Other"], None))
    monkeypatch.setattr(runtime_ui, "_ui_labels", lambda pid: (["Settings"], None))
    result = runtime_ui.runtime_ui_check(store, 1)
    assert not result.passed
    assert any("expected" in claim.detail for claim in result.claims)
    assert any("Settings" not in claim.detail for claim in result.claims)


def test_runtime_ui_window_inspection_unavailable(tmp_path: Path, monkeypatch) -> None:
    store = _store(tmp_path)
    _manifest(store, {"command": ["fake-app"]})
    monkeypatch.setattr(runtime_ui.subprocess, "Popen", lambda *a, **k: _FakeProcess())
    monkeypatch.setattr(runtime_ui.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(runtime_ui, "_window_titles", lambda pid: ([], "refused"))
    result = runtime_ui.runtime_ui_check(store, 1)
    assert not result.passed
    assert result.unknowns == ["native window inspection"]


def test_runtime_ui_process_exits_early(tmp_path: Path, monkeypatch) -> None:
    store = _store(tmp_path)
    _manifest(store, {"command": ["fake-app"]})

    class Exited(_FakeProcess):
        def __init__(self) -> None:
            super().__init__()
            self.returncode = 7

        def poll(self) -> int:
            return 7

    monkeypatch.setattr(runtime_ui.subprocess, "Popen", lambda *a, **k: Exited())
    monkeypatch.setattr(runtime_ui.time, "sleep", lambda _seconds: None)
    result = runtime_ui.runtime_ui_check(store, 1)
    assert not result.passed
    assert "code 7" in result.note


def test_runtime_ui_start_failure(tmp_path: Path, monkeypatch) -> None:
    store = _store(tmp_path)
    _manifest(store, {"command": ["fake-app"]})

    def fail(*args, **kwargs):
        raise OSError("cannot start")

    monkeypatch.setattr(runtime_ui.subprocess, "Popen", fail)
    result = runtime_ui.runtime_ui_check(store, 1)
    assert not result.passed
    assert "cannot start" in result.note


def test_window_titles_and_labels_handle_missing_tools(monkeypatch) -> None:
    monkeypatch.setattr(runtime_ui.shutil, "which", lambda name: None)
    assert runtime_ui._window_titles(1)[1] is not None
    assert runtime_ui._ui_labels(1)[1] is not None


def test_window_titles_linux_branch(monkeypatch) -> None:
    monkeypatch.setattr(runtime_ui.os, "name", "nt")
    monkeypatch.setattr(runtime_ui.shutil, "which", lambda name: "powershell")
    monkeypatch.setattr(
        runtime_ui.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, "Demo\n", ""),
    )
    assert runtime_ui._window_titles(1) == (["Demo"], None)
    monkeypatch.setattr(
        runtime_ui.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, "Start\nSettings\n", ""),
    )
    assert runtime_ui._ui_labels(1) == (["Start", "Settings"], None)
