from __future__ import annotations

import functools
import http.server
import importlib.util
import os
import sys
import threading
from pathlib import Path

import pytest

from rea_mcp.application.craft.service import run
from rea_mcp.application.project_store import ProjectStore

HAS_PLAYWRIGHT = importlib.util.find_spec("playwright") is not None


def _browser_present() -> bool:
    candidates = [
        Path(os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "")),
        Path.home() / ".cache" / "ms-playwright",
        Path.home() / "Library" / "Caches" / "ms-playwright",
    ]
    return any(str(path) and any(path.glob("chromium-*")) for path in candidates if path)


BROWSER_READY = HAS_PLAYWRIGHT and _browser_present()


@pytest.mark.real_engine
@pytest.mark.skipif(not BROWSER_READY, reason="requires playwright + a browser")
def test_craft_website_end_to_end(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "source"
    source.mkdir()
    html = '<html><body style="background:#eeeeee"><h1>Hello</h1><p>Welcome</p></body></html>'
    (source / "index.html").write_text(html, encoding="utf-8")

    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args) -> None:
            pass

    server = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0), functools.partial(Quiet, directory=str(source))
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        builder = tmp_path / "builder.py"
        builder.write_text(
            f"import pathlib\npathlib.Path('index.html').write_text({html!r})\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("REA_CRAFT_BUILDER_COMMAND", f"{sys.executable} {builder} {{prompt}}")
        result = run(
            target=f"http://127.0.0.1:{server.server_port}/",
            request="clone this page",
            project_dir=tmp_path / "project",
            name="website",
            rounds=1,
            good_enough=85,
        )
        assert result.ok
        assert result.value["ready"] is True
        loaded = ProjectStore.open(tmp_path / "project")
        assert loaded.ok
        assert loaded.value.capture_dir.joinpath("screenshot-1440.png").is_file()
        checks = loaded.value.latest_checks()
        assert [check.check for check in checks] == ["build", "web-visual"]
        assert checks[1].similarity is not None
        assert checks[1].similarity >= 85
    finally:
        server.shutdown()
        thread.join(timeout=5)
