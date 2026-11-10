"""Website capture used by craft study and checks."""

from __future__ import annotations

import contextlib
import http.server
import socket
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ...domain.analysis_error import AnalysisError, AnalysisInputError
from ...domain.result import Result, err, ok

DEFAULT_WIDTHS = [1440, 768, 390]


def _browser_executable() -> str | None:
    import os

    return os.environ.get("REA_BROWSER_EXECUTABLE")


def _layout_script() -> str:
    return """
() => {
  const visible = (el) => {
    const s = getComputedStyle(el);
    const r = el.getBoundingClientRect();
    return s.display !== 'none' && s.visibility !== 'hidden' && r.width > 0 && r.height > 0;
  };
  const text = (el) => (el.innerText || el.textContent || '').trim().replace(/\\s+/g, ' ');
  const headings = Array.from(document.querySelectorAll('h1,h2,h3,h4'))
    .filter(visible).slice(0, 80)
    .map(e => ({tag: e.tagName.toLowerCase(), text: text(e).slice(0, 300)}));
  const links = Array.from(document.querySelectorAll('a[href]'))
    .filter(visible).slice(0, 200)
    .map(e => ({text: text(e).slice(0, 120), href: e.getAttribute('href')}));
  const buttons = Array.from(document.querySelectorAll('button,input[type=button],input[type=submit]'))
    .filter(visible).slice(0, 100).map(e => text(e) || e.value || e.type);
  const inputs = Array.from(document.querySelectorAll('input,textarea,select'))
    .filter(visible).slice(0, 100).map(e => ({tag: e.tagName.toLowerCase(), type: e.type || '', placeholder: e.placeholder || ''}));
  const sections = Array.from(document.querySelectorAll('header,nav,main,section,article,footer,aside'))
    .filter(visible).slice(0, 120).map(e => {
      const r = e.getBoundingClientRect();
      const s = getComputedStyle(e);
      return {tag: e.tagName.toLowerCase(), x: Math.round(r.x), y: Math.round(r.y + scrollY), w: Math.round(r.width), h: Math.round(r.height), bg: s.backgroundColor, color: s.color, font: s.fontFamily, size: s.fontSize};
    });
  const all = Array.from(document.querySelectorAll('body *')).filter(visible).slice(0, 3000);
  const colors = Array.from(new Set(all.map(e => getComputedStyle(e).color).filter(Boolean))).slice(0, 40);
  const fonts = Array.from(new Set(all.map(e => getComputedStyle(e).fontFamily).filter(Boolean))).slice(0, 20);
  const body = document.body;
  return {
    url: location.href,
    title: document.title,
    viewport: {width: innerWidth, height: innerHeight},
    scrollWidth: Math.max(document.documentElement.scrollWidth, body ? body.scrollWidth : 0),
    scrollHeight: Math.max(document.documentElement.scrollHeight, body ? body.scrollHeight : 0),
    text: body ? text(body).slice(0, 12000) : '',
    headings, links, buttons, inputs, sections, colors, fonts,
    counts: {headings: headings.length, links: links.length, buttons: buttons.length, inputs: inputs.length, sections: sections.length},
  };
}
"""


def capture_website(
    url: str,
    output_dir: str | Path,
    *,
    widths: list[int] | None = None,
    deep: bool = False,
    timeout_ms: int | None = None,
) -> Result[dict[str, Any], AnalysisError]:
    try:
        from playwright.sync_api import sync_playwright
    except Exception as cause:
        return err(
            AnalysisInputError(
                operation="craft-study", message=f"playwright is unavailable: {cause}"
            )
        )
    from ..deadlines import timeout_ms as _timeout_ms

    timeout_ms = timeout_ms or _timeout_ms("capture", 30_000)
    out = Path(output_dir).expanduser()
    out.mkdir(parents=True, exist_ok=True)
    shots: list[str] = []
    pages: dict[str, Any] = {}
    html: str | None = None
    missing: list[str] = []
    try:
        with sync_playwright() as playwright:
            executable = _browser_executable()
            browser = (
                playwright.chromium.launch(executable_path=executable)
                if executable
                else playwright.chromium.launch()
            )
            try:
                page = browser.new_page()
                page.goto(url, wait_until="networkidle", timeout=timeout_ms)
                for width in widths or DEFAULT_WIDTHS:
                    page.set_viewport_size({"width": width, "height": 900})
                    page.wait_for_timeout(250)
                    layout = page.evaluate(_layout_script())
                    pages[str(width)] = layout
                    shot = out / f"screenshot-{width}.png"
                    page.screenshot(path=str(shot), full_page=True)
                    shots.append(str(shot))
                if deep:
                    html = page.content()
            finally:
                browser.close()
    except Exception as cause:
        return err(
            AnalysisInputError(operation="craft-study", message=f"website capture failed: {cause}")
        )
    if not shots:
        return err(
            AnalysisInputError(operation="craft-study", message="no screenshots were captured")
        )
    result = {
        "url": url,
        "widths": list(widths or DEFAULT_WIDTHS),
        "screenshots": shots,
        "pages": pages,
        "missing": missing,
    }
    if html is not None:
        (out / "page.html").write_text(html, encoding="utf-8")
        result["html"] = str(out / "page.html")
    import json

    (out / "capture.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return ok(result)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@contextlib.contextmanager
def serve_directory(directory: str | Path) -> Iterator[str]:
    root = Path(directory).expanduser().resolve()

    class Quiet(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, directory=str(root), **kwargs)

        def log_message(self, *args: Any) -> None:
            del args

    port = _free_port()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Quiet)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def site_directory(app_dir: str | Path) -> Path | None:
    root = Path(app_dir).expanduser()
    for candidate in (
        root / "dist",
        root / "build",
        root / "out",
        root / "public",
        root,
    ):
        if (candidate / "index.html").is_file():
            return candidate
    return None


def url_from_target(target: Any) -> str | None:
    if isinstance(target, dict):
        value = target.get("url")
        return str(value) if isinstance(value, str) else None
    return None


__all__ = [
    "DEFAULT_WIDTHS",
    "capture_website",
    "serve_directory",
    "site_directory",
    "url_from_target",
]
