from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image

from rea_mcp.application.checks.basic import visual_check
from rea_mcp.application.craft.service import run


def _fake_builder(tmp_path: Path) -> Path:
    script = tmp_path / "builder.py"
    script.write_text(
        "import pathlib\n"
        "pathlib.Path('index.html').write_text("
        "'<html><body style=\"background:#eeeeee\"><h1>Hello</h1><p>Welcome</p></body></html>'\n"
        ")\n"
        "print('built')\n",
        encoding="utf-8",
    )
    return script


def test_craft_run_with_fake_builder_reaches_ready(tmp_path: Path, monkeypatch) -> None:
    script = _fake_builder(tmp_path)
    monkeypatch.setenv("REA_CRAFT_BUILDER_COMMAND", f"{sys.executable} {script} {{prompt}}")
    result = run(
        target=None,
        request="make a page",
        project_dir=tmp_path / "project",
        name="demo",
        rounds=1,
    )
    assert result.ok
    assert result.value["ready"] is True
    assert result.value["project"]["status"] == "ready"
    checks = result.value["project"]["latest_checks"]
    assert [check["check"] for check in checks] == ["build"]


def test_visual_check_compares_screenshots(tmp_path: Path) -> None:
    def image(name: str, color: tuple[int, int, int]) -> Path:
        path = tmp_path / name
        Image.new("RGB", (320, 240), color).save(path)
        return path

    original_shot = image("original.png", (240, 240, 240))
    built_shot = image("built.png", (240, 240, 240))

    def capture(shot: Path) -> dict:
        return {
            "widths": [1440],
            "screenshots": [str(shot)],
            "pages": {
                "1440": {
                    "scrollWidth": 1440,
                    "scrollHeight": 240,
                    "text": "hello world",
                    "headings": [{"text": "Hello"}],
                    "colors": ["rgb(0,0,0)"],
                }
            },
        }

    result = visual_check(
        capture(original_shot), capture(built_shot), round_number=1, good_enough=80
    )
    assert result.passed is True
    assert result.similarity == 100.0
    assert not result.unknowns


def test_detect_game_engine(tmp_path: Path) -> None:
    from rea_mcp.application.craft.study import detect_game_engine

    (tmp_path / "project.godot").write_text("", encoding="utf-8")
    assert detect_game_engine(tmp_path) == {"engine": "godot", "clue": "project.godot"}


def test_game_self_test_check(tmp_path: Path) -> None:
    import json

    from rea_mcp.application.checks.basic import game_self_test
    from rea_mcp.application.project_store import create_project

    created = create_project(tmp_path / "game", name="game", request="build a game")
    assert created.ok
    store = created.value
    store.app_dir.mkdir(parents=True, exist_ok=True)
    (store.app_dir / "self-test.json").write_text(
        json.dumps(
            {
                "version": 1,
                "steps": [
                    {"step": "move", "passed": True},
                    {"step": "act", "passed": True},
                    {"step": "hud", "passed": True},
                ],
            }
        ),
        encoding="utf-8",
    )
    result = game_self_test(store, 1)
    assert result.passed is True
    assert len(result.claims) == 3


def test_api_builder_text_only(tmp_path: Path, monkeypatch) -> None:
    import http.server
    import json
    import threading

    content = json.dumps(
        {
            "files": {
                "index.html": "<html><body><h1>Hello</h1></body></html>",
                "style.css": "body { color: #111; }",
            },
            "summary": "built a page",
        }
    )

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            body = json.dumps(
                {
                    "choices": [{"message": {"content": content}}],
                    "usage": {"total_tokens": 42},
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            del args

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        monkeypatch.setenv("LLM_API_KEY", "sk-test")
        monkeypatch.setenv("LLM_API_URL", f"http://127.0.0.1:{server.server_port}/v1")
        monkeypatch.setenv("LLM_MODEL_NAME", "fake")
        result = run(
            target=None,
            request="make a page",
            project_dir=tmp_path / "api-project",
            name="api",
            builder="deepseek",
            rounds=1,
        )
        assert result.ok
        assert result.value["ready"] is True
        assert (tmp_path / "api-project/app/index.html").is_file()
        assert (tmp_path / "api-project/app/style.css").is_file()
        usage = result.value["project"]["usage"]
        assert usage["tokens"] == 42
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_runtime_smoke_check(tmp_path: Path) -> None:
    import json
    import sys

    from rea_mcp.application.checks.runtime import runtime_check
    from rea_mcp.application.project_store import create_project

    created = create_project(tmp_path / "runtime", name="runtime", request="app")
    assert created.ok
    store = created.value
    store.app_dir.mkdir(parents=True, exist_ok=True)
    (store.app_dir / "runtime.json").write_text(
        json.dumps({"command": [sys.executable, "-c", "import time; time.sleep(2)"]}),
        encoding="utf-8",
    )
    result = runtime_check(store, 1)
    assert result.passed is True
    assert result.check == "runtime-smoke"


def test_environment_check(tmp_path: Path) -> None:
    import json

    from rea_mcp.application.checks.environment import environment_check
    from rea_mcp.application.project_store import create_project

    capture = tmp_path / "capture"
    capture.mkdir()
    manifest = {
        "evidence_id": "ev_manifest",
        "normalized_result": {
            "kind": "environment-manifest",
            "parent_evidence_id": "ev_capture",
            "name": "demo",
            "tools": [
                {
                    "name": "health",
                    "method": "GET",
                    "path_template": "/health",
                    "parameters": {},
                    "record_ordinals": [0],
                }
            ],
        },
    }
    evidence = {
        "evidence_id": "ev_capture",
        "normalized_result": {
            "kind": "environment-capture",
            "artifact": {"sha256": "a" * 64},
            "entries": [
                {
                    "request": {"method": "GET", "url": "https://x/health"},
                    "response": {
                        "status": 200,
                        "content": {"mimeType": "text/plain", "text": "ok"},
                    },
                }
            ],
        },
    }
    (capture / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (capture / "evidence.json").write_text(json.dumps(evidence), encoding="utf-8")
    created = create_project(
        tmp_path / "project", name="env", request="check env", target=str(capture)
    )
    assert created.ok
    store = created.value
    from rea_mcp.application.craft.study import study_project

    assert study_project(store).ok
    store.app_dir.mkdir(parents=True, exist_ok=True)
    (store.app_dir / "environment.json").write_text(
        json.dumps(
            {
                "normalized_result": {
                    "kind": "environment-capture",
                    "entries": [
                        {
                            "request": {"method": "GET", "url": "https://x/health"},
                            "response": {
                                "status": 200,
                                "content": {"mimeType": "text/plain", "text": "ok"},
                            },
                        }
                    ],
                }
            }
        ),
        encoding="utf-8",
    )
    result = environment_check(store, 1)
    assert result.passed is True


def test_builder_failure_marks_project_failed(tmp_path: Path, monkeypatch) -> None:
    import sys

    script = tmp_path / "fail.py"
    script.write_text("raise SystemExit(7)\n", encoding="utf-8")
    monkeypatch.setenv("REA_CRAFT_BUILDER_COMMAND", f"{sys.executable} {script} {{prompt}}")
    result = run(
        target=None,
        request="fail",
        project_dir=tmp_path / "failed",
        rounds=1,
    )
    assert not result.ok
    from rea_mcp.application.project_store import ProjectStore

    loaded = ProjectStore.open(tmp_path / "failed")
    assert loaded.ok
    assert loaded.value.manifest.status == "failed"


def test_runtime_smoke_reports_nonzero_exit(tmp_path: Path) -> None:
    import json
    import sys

    from rea_mcp.application.checks.runtime import runtime_check
    from rea_mcp.application.project_store import create_project

    created = create_project(tmp_path / "runtime-bad", name="bad", request="app")
    assert created.ok
    store = created.value
    store.app_dir.mkdir(parents=True, exist_ok=True)
    (store.app_dir / "runtime.json").write_text(
        json.dumps({"command": [sys.executable, "-c", "raise SystemExit(3)"]}),
        encoding="utf-8",
    )
    result = runtime_check(store, 1)
    assert result.passed is False
    assert "3" in result.note


def test_environment_check_changed_and_missing_probe(tmp_path: Path) -> None:
    import json

    from rea_mcp.application.checks.environment import environment_check
    from rea_mcp.application.craft.study import study_project
    from rea_mcp.application.project_store import create_project

    capture = tmp_path / "capture"
    capture.mkdir()
    manifest = {
        "evidence_id": "ev_manifest",
        "normalized_result": {
            "kind": "environment-manifest",
            "parent_evidence_id": "ev_capture",
            "name": "demo",
            "tools": [
                {
                    "name": "health",
                    "method": "GET",
                    "path_template": "/health",
                    "parameters": {},
                    "record_ordinals": [0],
                }
            ],
        },
    }
    evidence = {
        "evidence_id": "ev_capture",
        "normalized_result": {
            "kind": "environment-capture",
            "artifact": {"sha256": "a" * 64},
            "entries": [
                {
                    "request": {"method": "GET", "url": "https://x/health"},
                    "response": {
                        "status": 200,
                        "content": {"mimeType": "text/plain", "text": "ok"},
                    },
                }
            ],
        },
    }
    (capture / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (capture / "evidence.json").write_text(json.dumps(evidence), encoding="utf-8")
    created = create_project(tmp_path / "project", name="env", request="x", target=str(capture))
    assert created.ok
    store = created.value
    assert study_project(store).ok
    store.app_dir.mkdir(parents=True, exist_ok=True)
    missing = environment_check(store, 1)
    assert missing.unknowns
    (store.app_dir / "environment.json").write_text(
        json.dumps(
            {
                "normalized_result": {
                    "kind": "environment-capture",
                    "entries": [
                        {
                            "request": {"method": "GET", "url": "https://x/health"},
                            "response": {
                                "status": 500,
                                "content": {"mimeType": "text/plain", "text": "no"},
                            },
                        }
                    ],
                }
            }
        ),
        encoding="utf-8",
    )
    changed = environment_check(store, 1)
    assert changed.passed is False
    assert changed.claims[0].passed is False
