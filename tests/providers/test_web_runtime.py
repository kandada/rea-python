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
