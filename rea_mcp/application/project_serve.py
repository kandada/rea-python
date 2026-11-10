"""A small read-only local dashboard for craft projects."""

from __future__ import annotations

import html
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlparse

from .project_store import ProjectStore


def _projects(root: Path) -> list[dict[str, Any]]:
    rows = []
    for path in sorted(root.glob("*/project.json")):
        loaded = ProjectStore.open(path.parent)
        if loaded.ok:
            rows.append(loaded.value.summary())
    return rows


def _project_page(project: dict[str, Any]) -> str:
    checks = project.get("latest_checks") or []
    inbox = project.get("inbox") or []
    check_rows = "".join(
        f"<tr><td>{html.escape(str(item.get('check')))}</td>"
        f"<td>{'pass' if item.get('passed') else 'needs work'}</td>"
        f"<td>{html.escape(str(item.get('similarity') or ''))}</td>"
        f"<td>{html.escape(str(item.get('note') or ''))}</td></tr>"
        for item in checks
    )
    inbox_rows = "".join(
        f"<li>{html.escape(str(item.get('question') or item.get('action')))} "
        f"<form method='post' action='/action' style='display:inline'>"
        f"<input type='hidden' name='project' value='{html.escape(str(project.get('root')))}'>"
        f"<input type='hidden' name='item' value='{html.escape(str(item.get('id')))}'>"
        f"<input name='value' placeholder='answer'><button>Answer</button></form></li>"
        for item in inbox
    )
    root = html.escape(str(project.get("root")))
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<title>{html.escape(str(project.get('name')))}</title>"
        "<style>body{font-family:system-ui;max-width:1000px;margin:2rem auto;padding:0 1rem}"
        "table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:.3rem}"
        "form{margin:.5rem 0}</style></head><body>"
        f"<p><a href='/'>← projects</a></p><h1>{html.escape(str(project.get('name')))}</h1>"
        f"<p>{html.escape(str(project.get('request')))}</p>"
        f"<p><b>{html.escape(str(project.get('status')))}</b> · {html.escape(str(project.get('mode')))}</p>"
        f"<form method='post' action='/action'><input type='hidden' name='project' value='{root}'>"
        "<button name='action' value='study'>Study</button>"
        "<button name='action' value='build'>Build</button>"
        "<button name='action' value='check'>Check</button></form>"
        f"<h2>Checks</h2><table><tr><th>check</th><th>status</th><th>similarity</th><th>note</th></tr>{check_rows}</table>"
        f"<h2>Inbox</h2><ul>{inbox_rows or '<li>empty</li>'}</ul>"
        f"<p><code>{root}</code></p></body></html>"
    )


def _page(root: Path) -> str:
    rows = _projects(root)
    cards = []
    for row in rows:
        checks = row.get("latest_checks") or []
        check_text = "<br>".join(
            f"{html.escape(str(item.get('check')))}: "
            f"{'pass' if item.get('passed') else 'needs work'}"
            for item in checks
        )
        cards.append(
            f"<article><h2>{html.escape(str(row.get('name')))}</h2>"
            f"<p>{html.escape(str(row.get('request')))}</p>"
            f"<p><b>{html.escape(str(row.get('status')))}</b> · "
            f"{html.escape(str(row.get('mode')))}</p>"
            f"<p>{check_text or 'no checks yet'}</p>"
            f"<a href='/project?path={quote(str(row.get('root')))}'>open</a> "
            f"<code>{html.escape(str(row.get('root')))}</code></article>"
        )
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>rea-python projects</title>"
        "<style>body{font-family:system-ui;max-width:1000px;margin:2rem auto;padding:0 1rem}"
        "article{border:1px solid #ddd;border-radius:8px;padding:1rem;margin:1rem 0}"
        "code{font-size:.8rem;color:#555}</style></head><body>"
        f"<h1>rea-python projects</h1><p>{len(rows)} project(s)</p>{''.join(cards)}</body></html>"
    )


def serve_projects(root: str | Path, *, host: str = "127.0.0.1", port: int = 18766) -> None:
    base = Path(root).expanduser().resolve()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)
            if parsed.path == "/api/projects":
                self._json(_projects(base))
                return
            if parsed.path == "/project":
                requested = Path(query.get("path", [""])[0]).expanduser().resolve()
                loaded = ProjectStore.open(requested)
                if not loaded.ok:
                    self.send_error(404)
                    return
                body = _project_page(loaded.value.summary()).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if parsed.path == "/api/project":
                requested = Path(query.get("path", [""])[0]).expanduser().resolve()
                loaded = ProjectStore.open(requested)
                self._json(loaded.value.summary() if loaded.ok else {"error": "not found"})
                return
            if parsed.path == "/api/tool-status":
                from .tool_status import tool_status

                self._json(tool_status())
                return
            if parsed.path in ("/", "/index.html"):
                body = _page(base).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_error(404)

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(min(length, 1_000_000))
                if "application/json" in (self.headers.get("Content-Type") or ""):
                    body = json.loads(raw or b"{}")
                else:
                    parsed_form = parse_qs(raw.decode("utf-8", errors="replace"))
                    body = {key: values[0] for key, values in parsed_form.items() if values}
            except (ValueError, OSError):
                self.send_error(400)
                return
            if parsed.path == "/action":
                from .craft.service import build, check, study

                project = Path(str(body.get("project") or "")).expanduser().resolve()
                loaded = ProjectStore.open(project)
                if not loaded.ok:
                    self.send_error(404)
                    return
                store = loaded.value
                action = str(body.get("action") or "")
                if action == "study":
                    study(store)
                elif action == "build":
                    build(store, builder=None)
                elif action == "check":
                    results = check(store)
                    del results
                elif action == "answer":
                    store.answer(str(body.get("item") or ""), str(body.get("value") or ""))
                elif action == "approve":
                    store.set_approval(str(body.get("kind") or ""), str(body.get("value") or ""))
                self.send_response(303)
                self.send_header("Location", f"/project?path={quote(str(project))}")
                self.end_headers()
                return
            if parsed.path not in ("/api/answer", "/api/approve") or not isinstance(body, dict):
                self.send_error(404)
                return
            project = Path(str(body.get("project") or "")).expanduser().resolve()
            loaded = ProjectStore.open(project)
            if not loaded.ok:
                self.send_error(404)
                return
            store = loaded.value
            if parsed.path == "/api/answer":
                result = store.answer(str(body.get("item") or ""), str(body.get("value") or ""))
                if not result.ok:
                    self._json({"error": result.error.message})
                    return
                self._json({"answered": result.value})
                return
            store.set_approval(str(body.get("kind") or ""), str(body.get("value") or ""))
            self._json({"project": store.summary()})

        def _json(self, value: object) -> None:
            body = json.dumps(value, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            del args

    server = ThreadingHTTPServer((host, port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"rea-python projects: http://{host}:{port}/")
    try:
        thread.join()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()


__all__ = ["serve_projects"]
