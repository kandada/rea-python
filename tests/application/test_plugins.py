from __future__ import annotations

from pathlib import Path

from rea_mcp.application.plugins import load_plugin_checks, run_plugin_checks
from rea_mcp.application.project_store import create_project


def test_python_plugin_check(tmp_path: Path, monkeypatch) -> None:
    plugin = tmp_path / "plugin.py"
    plugin.write_text(
        "from rea_mcp.domain.check import CheckResult\n"
        "class Check:\n"
        "    id = 'plugin-demo'\n"
        "    def run(self, store, round_number):\n"
        "        return CheckResult(self.id, round_number, True, 'plugin passed')\n"
        "CHECKS = [Check()]\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("REA_PLUGIN_PATHS", str(plugin))
    checks = load_plugin_checks()
    assert [check.id for check in checks] == ["plugin-demo"]
    created = create_project(tmp_path / "project", name="plugin", request="x")
    assert created.ok
    results = run_plugin_checks(created.value, 1)
    assert results[0].passed is True


def test_wasm_plugin_check(tmp_path: Path, monkeypatch) -> None:
    pytest = __import__("pytest")
    pytest.importorskip("wasmtime")
    import wasmtime

    wasm = tmp_path / "ok.wasm"
    wasm.write_bytes(wasmtime.wat2wasm('(module (func (export "check") (result i32) i32.const 1))'))
    monkeypatch.setenv("REA_WASM_PLUGINS", str(wasm))
    from rea_mcp.application.plugins import run_wasm_checks

    results = run_wasm_checks(object(), 1)
    assert results and results[0].passed is True


def test_wasm_plugin_without_check_export(tmp_path: Path, monkeypatch) -> None:
    pytest = __import__("pytest")
    pytest.importorskip("wasmtime")
    import wasmtime

    wasm = tmp_path / "empty.wasm"
    wasm.write_bytes(wasmtime.wat2wasm("(module)"))
    monkeypatch.setenv("REA_WASM_PLUGINS", str(wasm))
    from rea_mcp.application.plugins import run_wasm_checks

    results = run_wasm_checks(object(), 1)
    assert results and results[0].passed is False
    assert "no check export" in results[0].note
