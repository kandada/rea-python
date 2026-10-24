from __future__ import annotations

from pathlib import Path

from rea_mcp.domain.binary_target import parse_binary_target
from rea_mcp.providers.javascript import JavaScriptApplicationProvider


def _target(path: Path):
    result = parse_binary_target(path)
    assert result.ok
    return result.value


def _analyze(path: Path, parameters: dict | None = None) -> dict:
    result = JavaScriptApplicationProvider().analyze(
        "inspect_javascript_dataflow", _target(path), parameters or {}, None
    )  # type: ignore[arg-type]
    assert result.ok
    return result.value.result


def _app(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "app"
    root.mkdir()
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text, encoding="utf-8")
    return root


def test_cross_module_named_alias(tmp_path: Path) -> None:
    app = _app(
        tmp_path,
        {
            "source.js": 'export const token = sessionStorage.getItem("token");\n',
            "main.js": 'import { token as t } from "./source";\nfetch("/api", {body: t});\n',
        },
    )
    data = _analyze(app)
    assert data["exported_source_count"] == 1
    assert data["imported_source_count"] == 1
    assert any(
        row["module"] == "main.js" and row["source"] == "storage-get" and row["sink"] == "network"
        for row in data["flows"]
    )


def test_cross_module_require_destructure_and_member(tmp_path: Path) -> None:
    app = _app(
        tmp_path,
        {
            "source.js": (
                "const a = document.cookie;\nconst b = location.search;\n"
                "module.exports.a = a;\nmodule.exports.b = b;\n"
            ),
            "main.js": (
                'const { a: cookieValue } = require("./source");\n'
                'const search = require("./source").b;\n'
                'fetch("/x?c=" + cookieValue);\ndocument.write(search);\n'
            ),
        },
    )
    data = _analyze(app)
    flows = {(row["module"], row["source"], row["sink"]) for row in data["flows"]}
    assert ("main.js", "cookie", "network") in flows
    assert ("main.js", "location", "dom-html") in flows


def test_cross_module_default_import(tmp_path: Path) -> None:
    app = _app(
        tmp_path,
        {
            "source.js": "export default window.name;\n",
            "main.js": 'import value from "./source";\nlocalStorage.setItem("name", value);\n',
        },
    )
    data = _analyze(app)
    flows = {(row["module"], row["source"], row["sink"]) for row in data["flows"]}
    assert ("main.js", "window-name", "storage-set") in flows


def test_unresolved_imports_do_not_create_taint(tmp_path: Path) -> None:
    app = _app(
        tmp_path,
        {
            "main.js": 'import { token } from "./missing";\nfetch("/api?t=" + token);\n',
        },
    )
    data = _analyze(app)
    assert data["imported_source_count"] == 0
    assert data["flows"] == []


def test_source_and_sink_pagination(tmp_path: Path) -> None:
    app = _app(
        tmp_path,
        {
            "main.js": (
                "const one = event.data;\n"
                'const two = localStorage.getItem("two");\n'
                "const three = document.referrer;\n"
                'sessionStorage.setItem("one", one);\n'
                'fetch("/one", {body: two});\n'
                "location.assign(three);\n"
                "window.open(one);\n"
            )
        },
    )
    data = _analyze(
        app,
        {
            "offset": 1,
            "limit": 1,
            "operation_offset": 1,
            "operation_limit": 1,
            "sink_offset": 1,
            "sink_limit": 1,
        },
    )
    assert data["flow_count"] == 4
    assert len(data["flows"]) == 1
    assert data["flow_offset"] == 1
    assert data["next_flow_offset"] == 2
    assert len(data["operations"]) == 1
    assert len(data["sinks"]) == 1


def test_websocket_and_document_url_sources(tmp_path: Path) -> None:
    app = _app(
        tmp_path,
        {
            "main.js": (
                "socket.onmessage = (event) => {\n"
                "  const payload = event.data;\n"
                "  socket.send(payload);\n"
                "};\n"
                "const target = document.URL;\n"
                "window.open(target);\n"
            )
        },
    )
    data = _analyze(app)
    flows = {(row["source"], row["sink"]) for row in data["flows"]}
    assert ("message", "websocket") in flows
    assert ("document-url", "navigation") in flows
