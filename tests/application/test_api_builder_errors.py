from __future__ import annotations

import http.server
import json
import threading
from pathlib import Path

from rea_mcp.application.craft.api_builder import run_api_builder
from rea_mcp.application.project_store import create_project


class _Server:
    def __init__(self, status: int, payload: dict) -> None:
        self.status = status
        self.payload = payload
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                body = json.dumps(owner.payload).encode()
                self.send_response(owner.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                del args

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> str:
        self.thread.start()
        return f"http://127.0.0.1:{self.server.server_port}/v1"

    def __exit__(self, *args: object) -> None:
        self.server.shutdown()
        self.thread.join(timeout=5)


def _store(tmp_path: Path):
    created = create_project(tmp_path / "project", name="api", request="x")
    assert created.ok
    return created.value


def _env(monkeypatch, url: str) -> None:
    monkeypatch.setenv("LLM_API_KEY", "sk-test")
    monkeypatch.setenv("LLM_API_URL", url)
    monkeypatch.setenv("LLM_MODEL_NAME", "fake")


def test_api_builder_requires_environment(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    result = run_api_builder(_store(tmp_path), prompt="x")
    assert not result.ok
    assert "LLM_API_KEY" in result.error.message


def test_api_builder_http_error(tmp_path: Path, monkeypatch) -> None:
    with _Server(500, {"error": "no"}) as url:
        _env(monkeypatch, url)
        result = run_api_builder(_store(tmp_path), prompt="x")
    assert not result.ok
    assert "500" in result.error.message


def test_api_builder_missing_files_and_unsafe_path(tmp_path: Path, monkeypatch) -> None:
    with _Server(200, {"choices": [{"message": {"content": "{}"}}]}) as url:
        _env(monkeypatch, url)
        result = run_api_builder(_store(tmp_path / "one"), prompt="x")
    assert not result.ok
    unsafe = json.dumps({"files": {"../../escape.txt": "x"}})
    with _Server(200, {"choices": [{"message": {"content": unsafe}}]}) as url:
        _env(monkeypatch, url)
        result = run_api_builder(_store(tmp_path / "two"), prompt="x")
    assert not result.ok
    assert "unsafe" in result.error.message
