from __future__ import annotations

from rea_mcp.application.deadlines import timeout_ms, timeout_seconds


def test_deadlines_env(monkeypatch) -> None:
    monkeypatch.setenv("REA_CAPTURE_TIMEOUT_MS", "5000")
    assert timeout_ms("capture", 30000) == 5000
    assert timeout_seconds("capture", 30) == 5.0
    monkeypatch.setenv("REA_CAPTURE_TIMEOUT_MS", "bad")
    assert timeout_ms("capture", 30000) == 30000
    monkeypatch.setenv("REA_CAPTURE_TIMEOUT_MS", "0")
    assert timeout_ms("capture", 30000) == 30000
