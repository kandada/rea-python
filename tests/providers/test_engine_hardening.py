from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from rea_mcp.domain.binary_target import parse_binary_target
from rea_mcp.providers.engines import KunaProvider, _kuna_address, _kuna_function_slice
from rea_mcp.providers.web_runtime import (
    _electron_executable,
    _launch_electron,
    _stop_electron,
)


def test_kuna_function_slice_stops_at_next_label() -> None:
    text = "main:  ; 0x1000\n  nop\n\nhelper:  ; 0x2000\n  ret\n"
    assert _kuna_function_slice(text, "main") == "main:  ; 0x1000\n  nop\n"
    assert _kuna_function_slice(text, "helper") == "helper:  ; 0x2000\n  ret\n"
    assert _kuna_function_slice(text, "missing") is None


def test_kuna_address_prefers_hex_and_handles_decimal_fallback() -> None:
    assert _kuna_address({"address": 4294969720, "address_hex": "0x100000978"}) == "0x100000978"
    assert _kuna_address({"address": 16}) == "0x10"
    assert _kuna_address({}) is None


def test_kuna_supports_raw_binary(tmp_path: Path) -> None:
    raw = tmp_path / "firmware.bin"
    raw.write_bytes(b"\x90" * 16)
    target = parse_binary_target(raw, format_hint="raw-binary")
    assert target.ok
    assert KunaProvider().supports(target.value).code is None


def test_electron_executable_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REA_ELECTRON_EXECUTABLE", "/tmp/custom-electron")
    assert _electron_executable({}) == "/tmp/custom-electron"
    assert (
        _electron_executable({"executable": "/tmp/parameter-electron"}) == "/tmp/parameter-electron"
    )


def test_electron_launch_rejects_missing_executable_and_app(tmp_path: Path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    missing_exe = _launch_electron(
        {"app": str(app), "executable": str(tmp_path / "missing-electron")}
    )
    assert not missing_exe.ok
    missing_app = _launch_electron(
        {"app": str(tmp_path / "missing-app"), "executable": "/bin/true"}
    )
    assert not missing_app.ok


@pytest.mark.skipif(os.name == "nt", reason="process-group cleanup uses POSIX signals")
def test_electron_launch_reports_early_exit(tmp_path: Path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    executable = tmp_path / "electron"
    executable.write_text("#!/bin/sh\nexit 3\n", encoding="utf-8")
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    result = _launch_electron({"app": str(app), "executable": str(executable), "launch_timeout": 2})
    assert not result.ok
    assert "exited before exposing CDP" in result.error.message


@pytest.mark.skipif(os.name == "nt", reason="process-group cleanup uses POSIX signals")
def test_electron_launch_serves_cdp_and_is_stopped(tmp_path: Path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    executable = tmp_path / "electron"
    executable.write_text(
        """#!/usr/bin/env python3
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

port = 0
for argument in sys.argv:
    if argument.startswith("--remote-debugging-port="):
        port = int(argument.split("=", 1)[1])

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"Browser": "fake"}' if self.path == "/json/version" else b"[]"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass

HTTPServer(("127.0.0.1", port), Handler).serve_forever()
""",
        encoding="utf-8",
    )
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    launched = _launch_electron(
        {"app": str(app), "executable": str(executable), "launch_timeout": 5}
    )
    assert launched.ok
    process, endpoint, launch = launched.value
    try:
        assert endpoint.startswith("http://127.0.0.1:")
        assert launch["app"] == str(app)
        assert launch["executable"] == str(executable)
        assert launch["pid"] == process.pid
    finally:
        _stop_electron(process)
    assert process.poll() is not None
