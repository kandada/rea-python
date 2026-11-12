from __future__ import annotations

import io
import json

from rea_mcp.application import updater


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _fake_urlopen(url: str, timeout: float):
    return _Response(json.dumps({"info": {"version": "0.1.61"}}).encode())


def test_update_check_reports_upgrade(monkeypatch) -> None:
    monkeypatch.setattr(updater.urllib.request, "urlopen", _fake_urlopen)
    report = updater.update_report("0.1.60", check=True)
    assert report["latest_version"] == "0.1.61"
    assert report["upgrade_available"] is True
    assert "rea-mcp==0.1.61" in report["install_command"]
    assert report["release_url"].endswith("/0.1.61/")


def test_update_check_handles_errors(monkeypatch) -> None:
    def fail(url: str, timeout: float):
        raise OSError("offline")

    monkeypatch.setattr(updater.urllib.request, "urlopen", fail)
    report = updater.update_report("0.1.60", check=True)
    assert report["current_version"] == "0.1.60"
    assert report["upgrade_available"] is False
    assert "offline" in report["check_error"]


def test_update_offline_default() -> None:
    report = updater.update_report("0.1.60", check=False)
    assert report == {
        "current_version": "0.1.60",
        "channel": "source",
        "upgrade_available": False,
    }
