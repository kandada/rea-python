import asyncio
import json
from pathlib import Path
from typing import Any

from rea_mcp.composition.factories import create_binary_session
from rea_mcp.config.settings import AppConfig
from rea_mcp.server.app import build_mcp_server


async def _call(server: Any, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    result = await server.call_tool(name, arguments)
    if isinstance(result, tuple):  # (content, structured) on some SDK versions
        result = result[1] if isinstance(result[1], dict) else result[0]
    if isinstance(result, dict):
        return result
    for block in result:
        text = getattr(block, "text", None)
        if text:
            return json.loads(text)
    raise AssertionError(f"No structured result for {name}")


async def test_open_and_inspect(elf_file: Path) -> None:
    server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
    opened = await _call(server, "open_binary", {"path": str(elf_file)})
    assert opened["open"] is True
    assert opened["target"]["format"] == "elf"

    evidence = await _call(server, "inspect_binary_layout", {})
    assert evidence["evidence_id"].startswith("ev_")
    assert evidence["normalized_result"]["format"] == "elf"


async def test_binary_session_reports_bound_providers(elf_file: Path) -> None:
    server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
    await _call(server, "open_binary", {"path": str(elf_file)})
    status = await _call(server, "binary_session", {})
    assert status["open"] is True
    assert any(provider["id"] == "binary-layout" for provider in status["bound_providers"])


async def test_providers_tool() -> None:
    server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
    result = await _call(server, "providers", {})
    ids = {provider["id"] for provider in result["providers"]}
    assert {"binary-layout", "go", "rust", "sqlite"} <= ids


async def test_inspect_requires_open(tmp_path: Path) -> None:
    server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
    try:
        await _call(server, "inspect_binary_layout", {})
    except Exception as cause:
        assert "NO_TARGET_OPEN" in str(cause) or "No binary" in str(cause)
    else:
        raise AssertionError("inspect without an open target should fail")


async def test_evidence_export(elf_file: Path, tmp_path: Path) -> None:
    server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
    await _call(server, "open_binary", {"path": str(elf_file)})
    await _call(server, "inspect_go_binary", {})
    destination = tmp_path / "bundle.json"
    result = await _call(server, "evidence_export", {"path": str(destination)})
    assert result["record_count"] == 1
    assert destination.is_file()


async def test_doctor_tool() -> None:
    server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
    report = await _call(server, "doctor", {})
    assert "providers" in report
    assert any(entry["id"] == "binary-layout" for entry in report["providers"])


async def test_capture_process_tool() -> None:
    import sys

    server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
    result = await _call(
        server, "capture_process", {"command": [sys.executable, "-c", "print('hi')"]}
    )
    assert result["stdout"].strip() == "hi"


async def test_compare_evidence_tool(elf_file: Path, tmp_path: Path) -> None:
    server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
    await _call(server, "open_binary", {"path": str(elf_file)})
    evidence = await _call(server, "inspect_binary_layout", {})
    left = tmp_path / "left.json"
    right = tmp_path / "right.json"
    left.write_text(json.dumps(evidence), encoding="utf-8")
    right.write_text(json.dumps(evidence), encoding="utf-8")
    comparison = await _call(server, "compare_evidence", {"left": str(left), "right": str(right)})
    assert comparison["status"] == "unchanged"


async def test_target_content_tools_marked_untrusted() -> None:
    server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
    tools = {tool.name: tool for tool in await server.list_tools()}
    marked = tools["inspect_binary_layout"].meta
    assert marked is not None
    assert marked["provenance"]["untrusted_content"] is True
    assert tools["binary_session"].meta is None or "provenance" not in (
        tools["binary_session"].meta or {}
    )


async def test_response_budget_returns_summary(monkeypatch: Any, big_plist_file: Path) -> None:
    class _TightBudget:
        mcp_max_response_bytes = 1024

    monkeypatch.setattr("rea_mcp.server.app.AppConfig", lambda: _TightBudget())
    server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
    await _call(server, "open_binary", {"path": str(big_plist_file)})
    result = await _call(server, "inspect_plist", {})
    assert result["truncated"] is True
    assert result["reason"] == "response_budget"
    assert result["evidence_reference"]["evidence_id"].startswith("ev_")
    assert result["summary"]["operation"] == "inspect_plist"


async def test_runtime_oversized_result_is_retained(monkeypatch: Any) -> None:
    from types import SimpleNamespace

    from rea_mcp.domain.result import ok
    from rea_mcp.providers.base import AnalysisExecution, ProviderIdentity

    class _FakeProvider:
        def capabilities(self) -> list[Any]:
            return [SimpleNamespace(operation="observe_web_page")]

        def analyze(
            self, operation: str, target: Any, parameters: dict[str, Any], progress: Any
        ) -> Any:
            del operation, target, parameters, progress
            return ok(
                AnalysisExecution(
                    result={"blob": "x" * 5000},
                    provider=ProviderIdentity(id="fake", name="Fake", version="1"),
                )
            )

    class _TightBudget:
        mcp_max_response_bytes = 1024

    monkeypatch.setattr("rea_mcp.server.app.AppConfig", lambda: _TightBudget())
    monkeypatch.setattr("rea_mcp.server.app.build_providers", lambda: [_FakeProvider()])
    session = create_binary_session(AppConfig())
    server = build_mcp_server(session, AppConfig())
    result = await _call(server, "observe_web_page", {"url": "https://example.invalid"})
    assert result["truncated"] is True
    evidence_id = result["evidence_reference"]["evidence_id"]
    assert evidence_id.startswith("ev_")
    assert any(record.evidence_id == evidence_id for record in session.evidence_records())


async def test_evidence_bundle_defaults_to_summary(elf_file: Path) -> None:
    server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
    await _call(server, "open_binary", {"path": str(elf_file)})
    await _call(server, "inspect_binary_layout", {})
    summary = await _call(server, "get_evidence_bundle", {})
    assert summary["kind"] == "bundle"
    assert summary["record_count"] == 1
    full = await _call(server, "get_evidence_bundle", {"full": True})
    assert full["records"][0]["operation"] == "inspect_binary_layout"


def test_setup_install_skill_and_write_all(tmp_path: Path) -> None:
    from rea_mcp.application.setup import (
        KNOWN_CLIENT_CONFIGS,
        install_skill,
        write_all_registrations,
    )

    installed = install_skill(str(tmp_path / "skills"))
    assert installed.ok
    assert Path(installed.value["installed"]).is_file()

    written = write_all_registrations(str(tmp_path / "clients"))
    assert written.ok
    assert len(written.value["written"]) == len(KNOWN_CLIENT_CONFIGS)


async def test_runtime_tool_runs_without_open_target(monkeypatch: Any, tmp_path: Path) -> None:
    import http.server
    import threading

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/json/version":
                body: object = {"Browser": "Chrome/120"}
            else:
                body = [{"type": "page", "url": "https://example.com/"}]
            payload = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args: object) -> None:
            del args

    http_server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=http_server.serve_forever, daemon=True)
    thread.start()
    try:
        endpoint = f"http://127.0.0.1:{http_server.server_port}"
        server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
        result = await _call(server, "inspect_cdp_targets", {"endpoint": endpoint})
        assert result["target_count"] == 1
        assert result["browser"] == "Chrome/120"
    finally:
        http_server.shutdown()
        thread.join(timeout=5)


def test_client_preset_compacts_schemas() -> None:
    config = AppConfig(mcp_client="vscode")
    server = build_mcp_server(create_binary_session(config), config)
    tools = asyncio.run(server.list_tools())
    layout = next(tool for tool in tools if tool.name == "inspect_binary_layout")
    assert layout.outputSchema is None
    assert "properties" in layout.inputSchema
    assert "description" not in json.dumps(layout.inputSchema)


async def test_compat_alias_tools_registered() -> None:
    server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
    names = {tool.name for tool in await server.list_tools()}
    assert {
        "binary_overview",
        "analyze_function",
        "capture_process_scenario",
        "compare_artifacts",
        "export_evidence_bundle",
        "import_evidence_bundle",
        "inspect_web_network_capture",
    } <= names


def test_setup_merges_existing_client_config(tmp_path: Path) -> None:
    from rea_mcp.application.setup import write_registration

    config = tmp_path / "config.json"
    config.write_text(
        json.dumps({"theme": "dark", "mcpServers": {"other": {"command": "x"}}}),
        encoding="utf-8",
    )
    written = write_registration(str(config))
    assert written.ok
    data = json.loads(config.read_text(encoding="utf-8"))
    assert data["theme"] == "dark"
    assert data["mcpServers"]["other"]["command"] == "x"
    assert data["mcpServers"]["rea-mcp"]["args"] == ["-m", "rea_mcp", "mcp"]


def test_setup_merges_jsonc_config(tmp_path: Path) -> None:
    from rea_mcp.application.setup import _strip_jsonc, write_registration

    config = tmp_path / "config.jsonc"
    config.write_text(
        """
        {
          // existing client servers
          "mcpServers": {
            "other": {"command": "x"},
          },
          "theme": "dark",
        }
        """,
        encoding="utf-8",
    )
    written = write_registration(str(config))
    assert written.ok
    data = json.loads(_strip_jsonc(config.read_text(encoding="utf-8")))
    assert data["theme"] == "dark"
    assert data["mcpServers"]["other"]["command"] == "x"
    assert "rea-mcp" in data["mcpServers"]
    assert (tmp_path / "config.jsonc.bak").is_file()


def test_setup_edits_last_duplicate_member(tmp_path: Path) -> None:
    from rea_mcp.application.setup import _strip_jsonc, write_registration

    config = tmp_path / "config.jsonc"
    config.write_text(
        """
        {
          // first member is shadowed by the second
          "mcpServers": {"first": {"command": "a"}},
          "mcpServers": {"second": {"command": "b"}},
        }
        """,
        encoding="utf-8",
    )
    written = write_registration(str(config))
    assert written.ok
    assert written.value["edited_last_duplicate"] is True
    text = config.read_text(encoding="utf-8")
    assert '"first"' in text  # earlier duplicate preserved
    data = json.loads(_strip_jsonc(text))
    assert data["mcpServers"]["second"]["command"] == "b"
    assert "rea-mcp" in data["mcpServers"]


def test_truncate_result_text_adds_metadata() -> None:
    from rea_mcp.server.app import _truncate_result_text

    payload = {"normalized_result": {"pseudocode": "x" * 1000}}
    _truncate_result_text(payload, 100)
    result = payload["normalized_result"]
    assert result["pseudocode"] == "x" * 100
    assert result["pseudocode_bytes"] == 1000
    assert result["pseudocode_truncated"] is True

    untouched = {"normalized_result": {"pseudocode": "abc"}}
    _truncate_result_text(untouched, 100)
    assert untouched["normalized_result"] == {"pseudocode": "abc"}


async def test_managed_tool_surface_matches_upstream() -> None:
    server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
    names = {tool.name for tool in await server.list_tools()}
    for name in (
        "inspect_managed_artifact",
        "inspect_managed_members",
        "inspect_managed_native_boundaries",
        "compare_managed_members",
        "verify_managed_native_boundaries",
        "import_managed_reconstruction",
        "project_managed_application_graph",
    ):
        assert name in names


async def test_managed_members_summary_mcp(pe_clr_file: Path) -> None:
    server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
    result = await _call(
        server,
        "inspect_managed_members",
        {
            "path": str(pe_clr_file),
            "type_names": ["MyNamespace.MyType"],
            "detail": "summary",
        },
    )
    assert result["kind"] == "managed-member-summary"
    assert result["reported_counts"]["methods"] == 1
    assert result["selection"]["unmatched_type_names"] == []


def test_http_transport_settings(monkeypatch: Any) -> None:
    from types import SimpleNamespace

    from rea_mcp.server.app import run_mcp_http_server

    captured: dict[str, Any] = {}
    settings = SimpleNamespace(
        host="",
        port=0,
        streamable_http_path="",
        json_response=False,
        transport_security=SimpleNamespace(allowed_hosts=[]),
    )

    class _App:
        def add_middleware(self, middleware: Any, **kwargs: Any) -> None:
            captured["middleware"] = middleware
            captured["middleware_kwargs"] = kwargs

    class _Server:
        def __init__(self) -> None:
            self.settings = settings

        def streamable_http_app(self) -> _App:
            return _App()

    monkeypatch.setattr("rea_mcp.server.app.build_mcp_server", lambda *args, **kwargs: _Server())
    monkeypatch.setattr("uvicorn.run", lambda *args, **kwargs: captured.update(run=kwargs))
    run_mcp_http_server(
        create_binary_session(AppConfig()), AppConfig(), host="0.0.0.0", port=9001, path="/x"
    )
    assert captured["run"]["port"] == 9001
    assert settings.host == "0.0.0.0"
    assert settings.port == 9001
    assert settings.streamable_http_path == "/x"
    assert settings.json_response is True
    assert captured["middleware"].__name__ == "HttpBudgetMiddleware"


async def test_managed_workflow_tools_call(pe_clr_file: Path) -> None:
    server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
    boundaries = await _call(
        server, "inspect_managed_native_boundaries", {"path": str(pe_clr_file)}
    )
    assert "pinvoke" in boundaries
    verified = await _call(
        server,
        "verify_managed_native_boundaries",
        {"managed": str(pe_clr_file), "boundaries": ["MyMethod"]},
    )
    assert "boundaries" in verified
    graph = await _call(server, "project_managed_application_graph", {"path": str(pe_clr_file)})
    assert graph["nodes"]
    assert any(node["kind"] == "method" for node in graph["nodes"])


async def test_http_budget_middleware_retains_oversized_result() -> None:
    from rea_mcp.server.transport import HttpBudgetMiddleware

    async def app(scope: Any, receive: Any, send: Any) -> None:
        del scope, receive
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": json.dumps(
                    {"jsonrpc": "2.0", "id": 7, "result": {"value": "x" * 500}}
                ).encode(),
            }
        )

    retained: list[dict[str, Any]] = []

    def retain(operation: str, payload: dict[str, Any]) -> str:
        retained.append({"operation": operation, "payload": payload})
        return "ev_http"

    middleware = HttpBudgetMiddleware(app, budget_bytes=64, retain=retain)
    messages: list[dict[str, Any]] = []

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    await middleware({"type": "http"}, None, send)
    body = json.loads(messages[-1]["body"])
    assert body["id"] == 7
    assert body["error"]["data"]["evidence_reference"]["evidence_id"] == "ev_http"
    assert retained[0]["operation"] == "mcp-http"


async def test_project_android_graph_mcp(apk_file: Path) -> None:
    server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
    graph = await _call(server, "project_android_application_graph", {"path": str(apk_file)})
    assert graph["nodes"]
    assert graph["root"]


async def test_application_graph_workflows(js_dir: Path, tmp_path: Path) -> None:
    server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
    compared = await _call(
        server,
        "compare_application_versions",
        {"left": str(js_dir), "right": str(js_dir)},
    )
    assert compared["status"] == "unchanged"
    traced = await _call(
        server,
        "trace_application_feature",
        {"path": str(js_dir), "feature": "renderer"},
    )
    assert traced["status"] == "matched"
    semantics = await _call(
        server,
        "trace_javascript_semantics",
        {"path": str(js_dir), "node": "main.js"},
    )
    assert semantics["status"] == "observed"


async def test_http_sse_budget_middleware() -> None:
    from rea_mcp.server.transport import HttpBudgetMiddleware

    async def app(scope: Any, receive: Any, send: Any) -> None:
        del scope, receive
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/event-stream")],
            }
        )
        await send({"type": "http.response.body", "body": b"event: message\n", "more_body": True})
        await send(
            {
                "type": "http.response.body",
                "body": b'data: {"jsonrpc":"2.0","id":1,"result":{"value":"'
                + b"x" * 500
                + b'"}}\n',
                "more_body": False,
            }
        )

    retained: list[str] = []

    def retain(operation: str, payload: dict[str, Any]) -> str:
        retained.append(operation)
        return "ev_sse"

    middleware = HttpBudgetMiddleware(app, budget_bytes=64, retain=retain)
    messages: list[dict[str, Any]] = []

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    await middleware({"type": "http"}, None, send)
    body = b"".join(
        message.get("body", b"") for message in messages if message["type"] == "http.response.body"
    )
    assert b"RESOURCE_CONSTRAINT" in body
    assert b"ev_sse" in body
    assert retained == ["mcp-http-sse"]


async def test_triage_tool_returns_compact_evidence(elf_file: Path) -> None:
    server = build_mcp_server(create_binary_session(AppConfig()), AppConfig())
    result = await _call(server, "triage", {"path": str(elf_file), "question": "what is this?"})
    assert result["kind"] == "triage"
    assert result["target"]["format"] == "elf"
    assert result["evidence_ids"]
    assert result["probe_count"] >= 1
