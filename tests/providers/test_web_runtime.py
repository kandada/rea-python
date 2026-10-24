import http.server
import importlib.util
import json
import os
import threading
from pathlib import Path

import pytest

from rea_mcp.domain.binary_target import parse_binary_target
from rea_mcp.providers.web_runtime import WebRuntimeProvider

HAS_PLAYWRIGHT = importlib.util.find_spec("playwright") is not None


def _browser_present() -> bool:
    candidates = [
        Path(os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "")),
        Path.home() / ".cache" / "ms-playwright",
        Path.home() / "Library" / "Caches" / "ms-playwright",
    ]
    return any(str(path) and any(path.glob("chromium-*")) for path in candidates if path)


BROWSER_READY = HAS_PLAYWRIGHT and _browser_present()


@pytest.fixture
def web_url(tmp_path: Path) -> str:
    override = os.environ.get("REA_BROWSER_TEST_URL")
    if override:
        return override
    page = tmp_path / "page.html"
    page.write_text(
        "<html><head><title>REA Test Page</title></head><body><script>1</script></body></html>",
        encoding="utf-8",
    )
    return page.as_uri()


def _target(path: Path):
    result = parse_binary_target(path)
    assert result.ok
    return result.value


@pytest.mark.real_engine
@pytest.mark.skipif(not BROWSER_READY, reason="requires playwright + an installed browser")
def test_inspect_web_page_real(plain_file: Path, web_url: str) -> None:
    result = WebRuntimeProvider().analyze(
        "inspect_web_page", _target(plain_file), {"url": web_url}, None
    )
    assert result.ok
    assert "REA Test Page" in result.value.result["title"]
    assert result.value.result["script_count"] >= 1


@pytest.mark.real_engine
@pytest.mark.skipif(not BROWSER_READY, reason="requires playwright + an installed browser")
def test_capture_screenshot_and_session(plain_file: Path, tmp_path: Path, web_url: str) -> None:
    destination = tmp_path / "page.png"
    shot = WebRuntimeProvider().analyze(
        "capture_web_screenshot",
        _target(plain_file),
        {"url": web_url, "output": str(destination)},
        None,
    )
    assert shot.ok
    assert destination.is_file() and destination.stat().st_size > 0
    session = WebRuntimeProvider().analyze(
        "observe_web_session", _target(plain_file), {"url": web_url}, None
    )
    assert session.ok
    assert session.value.result["title"]


@pytest.mark.real_engine
@pytest.mark.skipif(not BROWSER_READY, reason="requires playwright + an installed browser")
def test_inspect_event_listeners_real(plain_file: Path, web_url: str) -> None:
    result = WebRuntimeProvider().analyze(
        "inspect_web_event_listeners", _target(plain_file), {"url": web_url}, None
    )
    assert result.ok
    assert "inline_handlers" in result.value.result


def test_analyze_web_bundle(js_dir: Path, plain_file: Path) -> None:
    result = WebRuntimeProvider().analyze(
        "analyze_web_bundle", _target(plain_file), {"path": str(js_dir)}, None
    )
    assert result.ok
    modules = {edge["module"] for edge in result.value.result["imports"]}
    assert "./renderer" in modules


def test_list_browser_targets_cdp(plain_file: Path) -> None:
    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            payload = json.dumps(
                [{"type": "page", "title": "T", "url": "https://example.com/"}]
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args: object) -> None:
            del args

    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        endpoint = f"http://127.0.0.1:{server.server_port}"
        result = WebRuntimeProvider().analyze(
            "list_browser_targets", _target(plain_file), {"endpoint": endpoint}, None
        )
        assert result.ok
        assert result.value.result["target_count"] == 1
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.fixture
def body_endpoint() -> str:
    payload = b'{"data":"' + b"x" * 100_000 + b'"}'
    page = b"<html><body>ok<script>fetch('/data').then(r=>r.text())</script></body></html>"

    class _Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            body = payload if self.path == "/data" else page
            content_type = "application/json" if self.path == "/data" else "text/html"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            del args

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()


@pytest.mark.real_engine
@pytest.mark.skipif(not BROWSER_READY, reason="requires playwright + an installed browser")
def test_observe_web_execution_caps_bodies(plain_file: Path, body_endpoint: str) -> None:
    result = WebRuntimeProvider().analyze(
        "observe_web_execution",
        _target(plain_file),
        {
            "url": body_endpoint,
            "duration": 2.0,
            "capture_bodies": True,
            "retain_bodies": True,
        },
        None,
    )
    assert result.ok
    data = result.value.result
    assert data["bodies_captured"] is True
    assert data["body_bytes_total"] <= 512_000
    assert data["bodies_truncated"] is True
    bodies = [item for item in data["responses"] if item["url"].endswith("/data")]
    assert bodies
    assert bodies[0]["body_truncated"] is True
    assert len(bodies[0]["body"]) <= 32_000
    assert data["retained_body_bytes"] >= 100_000
    assert data["retained_bodies_truncated"] is False
    assert len(data["retained_bodies"][0]["body"]) >= 100_000


@pytest.mark.real_engine
@pytest.mark.skipif(not BROWSER_READY, reason="requires playwright + an installed browser")
def test_discover_webmcp_runtime_registration(plain_file: Path, tmp_path: Path) -> None:
    page = tmp_path / "webmcp.html"
    page.write_text(
        "<html><body><script>navigator.modelContext.registerTool({name: 'search', description: 'd', inputSchema: {type: 'object'}});</script></body></html>",
        encoding="utf-8",
    )
    result = WebRuntimeProvider().analyze(
        "discover_webmcp_tools", _target(plain_file), {"url": page.as_uri()}, None
    )
    assert result.ok
    data = result.value.result
    assert data["tool_count"] == 1
    assert data["registered_tools"][0]["name"] == "search"


@pytest.mark.real_engine
@pytest.mark.skipif(not BROWSER_READY, reason="requires playwright + an installed browser")
def test_invoke_webmcp_tool(plain_file: Path, tmp_path: Path) -> None:
    page = tmp_path / "invoke.html"
    page.write_text(
        "<html><body><script>navigator.modelContext.registerTool({name: 'echo', execute: async (args) => ({echo: args.value})});</script></body></html>",
        encoding="utf-8",
    )
    result = WebRuntimeProvider().analyze(
        "invoke_webmcp_tool",
        _target(plain_file),
        {"url": page.as_uri(), "name": "echo", "arguments": {"value": 7}},
        None,
    )
    assert result.ok
    data = result.value.result
    assert data["status"] == "called"
    assert data["result"]["echo"] == 7


@pytest.mark.real_engine
@pytest.mark.skipif(not BROWSER_READY, reason="requires playwright + an installed browser")
def test_event_listener_source_location(tmp_path: Path, plain_file: Path) -> None:
    page = tmp_path / "listener.html"
    page.write_text(
        '<button id="x">go</button><script>\n'
        "document.querySelector('#x').addEventListener('click', function hello(){ fetch('/api'); });\n"
        "</script>",
        encoding="utf-8",
    )
    result = WebRuntimeProvider().analyze(
        "inspect_web_event_listeners",
        _target(plain_file),
        {"url": page.as_uri(), "selector": "#x"},
        None,
    )
    assert result.ok
    assert result.value.result["listener_count"] == 1
    listener = result.value.result["listeners"][0]
    assert listener["type"] == "click"
    assert listener["script_url"] == page.as_uri()
    assert "addEventListener" in (listener["source_line"] or "")


@pytest.mark.real_engine
@pytest.mark.skipif(not BROWSER_READY, reason="requires playwright + an installed browser")
def test_browser_scenario_actions(tmp_path: Path, plain_file: Path) -> None:
    page = tmp_path / "scenario.html"
    shot = tmp_path / "shot.png"
    page.write_text(
        "<input id='x'><button id='b' onclick=\"document.title='clicked'\">go</button>",
        encoding="utf-8",
    )
    result = WebRuntimeProvider().analyze(
        "capture_browser_scenario",
        _target(plain_file),
        {
            "steps": [
                {"action": "goto", "url": page.as_uri()},
                {"action": "fill", "selector": "#x", "value": "hello"},
                {"action": "click", "selector": "#b"},
                {"action": "wait", "seconds": 0.01},
                {"action": "screenshot", "path": str(shot)},
            ]
        },
        None,
    )
    assert result.ok
    assert [step["action"] for step in result.value.result["steps"]] == [
        "goto",
        "fill",
        "click",
        "wait",
        "screenshot",
    ]
    assert shot.is_file()


@pytest.mark.real_engine
@pytest.mark.skipif(not BROWSER_READY, reason="requires playwright + an installed browser")
def test_observe_web_session_storage_and_title(tmp_path: Path, plain_file: Path) -> None:
    page = tmp_path / "session.html"
    page.write_text(
        "<title>Session</title><script>localStorage.setItem('k','v');"
        "sessionStorage.setItem('s','v');</script>",
        encoding="utf-8",
    )
    result = WebRuntimeProvider().analyze(
        "observe_web_session", _target(plain_file), {"url": page.as_uri()}, None
    )
    assert result.ok
    assert result.value.result["title"] == "Session"
    assert result.value.result["storage"]["local"] == ["k"]
    assert result.value.result["storage"]["session"] == ["s"]


def test_compare_web_screenshots_hashes(tmp_path: Path, plain_file: Path) -> None:
    left = tmp_path / "left.png"
    right = tmp_path / "right.png"
    left.write_bytes(b"same")
    right.write_bytes(b"same")
    provider = WebRuntimeProvider()
    unchanged = provider.analyze(
        "compare_web_screenshots",
        _target(plain_file),
        {"left": str(left), "right": str(right)},
        None,
    )
    assert unchanged.ok
    assert unchanged.value.result["status"] == "unchanged"
    right.write_bytes(b"different")
    changed = provider.analyze(
        "compare_web_screenshots",
        _target(plain_file),
        {"left": str(left), "right": str(right)},
        None,
    )
    assert changed.ok
    assert changed.value.result["status"] == "changed"


@pytest.mark.real_engine
@pytest.mark.skipif(not BROWSER_READY, reason="requires playwright + an installed browser")
def test_web_runtime_required_argument_errors(plain_file: Path) -> None:
    provider = WebRuntimeProvider()
    target = _target(plain_file)
    cases = [
        ("capture_web_screenshot", {"url": "about:blank"}),
        ("capture_web_screenshot", {"output": "x.png"}),
        ("export_web_scripts", {"url": "about:blank"}),
        ("recover_javascript_sources", {"output": "out"}),
        ("trace_web_module_imports", {}),
        ("trace_web_source_location", {"source_url": "about:blank"}),
    ]
    for operation, parameters in cases:
        result = provider.analyze(operation, target, parameters, None)
        assert not result.ok, operation


@pytest.fixture
def script_endpoint() -> str:
    class _Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            if self.path == "/app.js":
                body = (
                    b'import { x } from "/dep.js";\n'
                    b'const token = localStorage.getItem("token");\n'
                    b'fetch("/api?t=" + token);\n'
                    b"//# sourceMappingURL=app.js.map\n"
                )
                content_type = "application/javascript"
            elif self.path == "/app.js.map":
                body = json.dumps(
                    {"sources": ["orig.js"], "sourcesContent": ["const original = 1;\n"]}
                ).encode()
                content_type = "application/json"
            elif self.path == "/dep.js":
                body = b"export const x = 1;\n"
                content_type = "application/javascript"
            else:
                body = b'<html><body><script src="/app.js"></script></body></html>'
                content_type = "text/html"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            del args

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()


@pytest.mark.real_engine
@pytest.mark.skipif(not BROWSER_READY, reason="requires playwright + an installed browser")
def test_export_trace_and_recover_web_scripts(
    plain_file: Path, tmp_path: Path, script_endpoint: str
) -> None:
    provider = WebRuntimeProvider()
    target = _target(plain_file)
    exported = provider.analyze(
        "export_web_scripts",
        target,
        {"url": script_endpoint, "output": str(tmp_path / "exported")},
        None,
    )
    assert exported.ok
    assert exported.value.result["exported_count"] == 1
    assert Path(exported.value.result["exported"][0]["path"]).is_file()
    traced = provider.analyze("trace_web_module_imports", target, {"url": script_endpoint}, None)
    assert traced.ok
    assert any(edge["module"] == "/dep.js" for edge in traced.value.result["edges"])
    recovered = provider.analyze(
        "recover_javascript_sources",
        target,
        {"url": script_endpoint, "output": str(tmp_path / "recovered")},
        None,
    )
    assert recovered.ok
    assert recovered.value.result["source_count"] == 1
    located = provider.analyze(
        "trace_web_source_location",
        target,
        {"source_url": f"{script_endpoint}app.js", "symbol": "token"},
        None,
    )
    assert located.ok
    assert located.value.result["matches"]


@pytest.fixture
def cdp_endpoint() -> str:
    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            payload = json.dumps(
                [
                    {"type": "page", "title": "P", "url": "https://example.com/"},
                    {"type": "worker", "title": "W", "url": "https://example.com/w.js"},
                ]
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args: object) -> None:
            del args

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_cdp_target_operations(plain_file: Path, cdp_endpoint: str) -> None:
    provider = WebRuntimeProvider()
    target = _target(plain_file)
    page = provider.analyze("inspect_electron_page", target, {"endpoint": cdp_endpoint}, None)
    assert page.ok
    assert page.value.result["page"]["title"] == "P"
    observed = provider.analyze(
        "observe_javascript_runtime", target, {"endpoint": cdp_endpoint}, None
    )
    assert observed.ok
    assert observed.value.result["targets"]
    electron = provider.analyze("list_electron_targets", target, {"endpoint": cdp_endpoint}, None)
    assert electron.ok
    assert electron.value.result["target_count"] == 1
    runtime = provider.analyze(
        "list_javascript_runtime_targets", target, {"endpoint": cdp_endpoint}, None
    )
    assert runtime.ok
    assert runtime.value.result["target_count"] == 2
    reconciled = provider.analyze(
        "reconcile_javascript_runtime", target, {"endpoint": cdp_endpoint}, None
    )
    assert reconciled.ok
    assert reconciled.value.result["added"] == []
    assert reconciled.value.result["removed"] == []


def test_cdp_unavailable_endpoint_reports_capability_error(plain_file: Path) -> None:
    result = WebRuntimeProvider().analyze(
        "inspect_electron_page",
        _target(plain_file),
        {"endpoint": "http://127.0.0.1:1"},
        None,
    )
    assert not result.ok
    assert "no CDP endpoint" in result.error.message
