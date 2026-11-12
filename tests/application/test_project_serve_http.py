from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

from rea_mcp.application.project_store import create_project


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait(url: str, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(url, timeout=0.5).read()
            return
        except (OSError, urllib.error.URLError):
            time.sleep(0.1)
    raise AssertionError(f"server did not start: {url}")


def _get(url: str) -> bytes:
    return urllib.request.urlopen(url, timeout=5).read()


def _post_json(url: str, payload: dict) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    return json.loads(urllib.request.urlopen(request, timeout=5).read())


def _post_form(url: str, payload: dict) -> bytes:
    request = urllib.request.Request(
        url,
        data=urllib.parse.urlencode(payload).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    return urllib.request.urlopen(request, timeout=5).read()


@pytest.mark.slow
def test_project_dashboard_http_endpoints(tmp_path: Path) -> None:
    created = create_project(tmp_path / "demo", name="Demo", request="inspect it", mode="deep")
    assert created.ok
    store = created.value
    asked = store.ask("Which entry point?")
    port = _free_port()
    root = Path(__file__).resolve().parents[2]
    env = {**os.environ, "PYTHONPATH": str(root)}
    code = (
        "from rea_mcp.application.project_serve import serve_projects;"
        f"serve_projects({str(tmp_path)!r}, host='127.0.0.1', port={port})"
    )
    process = subprocess.Popen(
        [sys.executable, "-c", code],
        cwd=str(root),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        _wait(f"{base}/api/projects")
        projects = json.loads(_get(f"{base}/api/projects"))
        assert projects[0]["name"] == "Demo"
        assert b"rea-python projects" in _get(f"{base}/")
        project = json.loads(
            _get(f"{base}/api/project?{urllib.parse.urlencode({'path': store.root})}")
        )
        assert project["name"] == "Demo"
        assert b"Demo" in _get(f"{base}/project?{urllib.parse.urlencode({'path': store.root})}")
        assert isinstance(json.loads(_get(f"{base}/api/tool-status")), dict)

        answered = _post_json(
            f"{base}/api/answer",
            {"project": str(store.root), "item": asked["id"], "value": "main"},
        )
        assert answered["answered"]["answer"] == "main"
        approved = _post_json(
            f"{base}/api/approve",
            {"project": str(store.root), "kind": "commands", "value": "ask"},
        )
        assert approved["project"]["approvals"]["commands"] == "ask"
        _post_form(f"{base}/action", {"project": str(store.root), "action": "check"})
        with pytest.raises(urllib.error.HTTPError) as missing:
            _get(f"{base}/project?{urllib.parse.urlencode({'path': str(tmp_path / 'missing')})}")
        assert missing.value.code == 404
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
