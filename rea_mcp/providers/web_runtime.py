"""Web, Electron and JavaScript runtime observation via Playwright and CDP.

Playwright is optional and caller-supplied. CDP-only operations use the HTTP
debug endpoint; page operations need ``playwright`` and a Chrome-family browser.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shlex
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..domain.analysis_error import (
    AnalysisCapabilityUnavailableError,
    AnalysisError,
    AnalysisInputError,
)
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .external import optional_import
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="web-runtime", name="REA-Python web runtime", version="1")
_OPERATIONS = (
    "list_browser_targets",
    "list_electron_targets",
    "list_javascript_runtime_targets",
    "inspect_web_page",
    "inspect_web_event_listeners",
    "observe_web_execution",
    "observe_web_session",
    "capture_web_screenshot",
    "compare_web_screenshots",
    "capture_browser_scenario",
    "capture_electron_scenario",
    "inspect_electron_page",
    "observe_javascript_runtime",
    "reconcile_javascript_runtime",
    "analyze_web_bundle",
    "export_web_scripts",
    "recover_javascript_sources",
    "trace_web_module_imports",
    "trace_web_source_location",
    "discover_webmcp_tools",
    "invoke_webmcp_tool",
    "trace_native_ui_action",
)
_CDP_OPERATIONS = {
    "list_browser_targets",
    "list_electron_targets",
    "list_javascript_runtime_targets",
    "inspect_electron_page",
    "observe_javascript_runtime",
    "reconcile_javascript_runtime",
    "capture_electron_scenario",
}
_MAX_BODY_BYTES = 32_000
_MAX_TOTAL_BODY_BYTES = 512_000
_MAX_RETAINED_BODY_BYTES = 8 * 1024 * 1024
_SCRIPT_RE = re.compile(r"""(?:import\s[^;]*?from\s*|require\s*\(\s*)["']([^"']+)["']""")


def _endpoint(parameters: dict[str, Any]) -> str:
    return str(
        parameters.get("endpoint") or os.environ.get("REA_CDP_URL") or "http://127.0.0.1:9222"
    ).rstrip("/")


def _http_json(url: str, timeout: float = 5.0) -> Any:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8", "replace"))


def _electron_executable(parameters: dict[str, Any]) -> str | None:
    configured = parameters.get("executable") or os.environ.get("REA_ELECTRON_EXECUTABLE")
    if configured:
        return str(configured)
    for root in (Path.cwd(), Path(__file__).resolve().parents[3]):
        candidate = root / "vendor/tools/electron/node_modules/.bin/electron"
        if candidate.is_file():
            return str(candidate)
    return None


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _launch_electron(
    parameters: dict[str, Any],
) -> Result[tuple[subprocess.Popen[bytes], str, dict[str, Any]], AnalysisError]:
    executable = _electron_executable(parameters)
    app = str(parameters.get("app") or "")
    if not executable or not Path(executable).is_file():
        return err(
            AnalysisCapabilityUnavailableError(
                message="Electron executable was not found",
                provider_id=_PROVIDER.id,
                operation="capture_electron_scenario",
                reason="provider_unavailable",
                remediation_action=(
                    "Install Electron under vendor/tools/electron or set REA_ELECTRON_EXECUTABLE."
                ),
            )
        )
    if not app or not Path(app).exists():
        return err(
            AnalysisInputError(
                operation="capture_electron_scenario", message="app path does not exist"
            )
        )
    port = int(parameters.get("port") or 0) or _free_port()
    extra = parameters.get("launch_args") or []
    if isinstance(extra, str):
        extra = shlex.split(extra)
    arguments = [
        executable,
        app,
        f"--remote-debugging-port={port}",
        *[str(item) for item in extra if str(item)],
    ]
    try:
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=os.name == "posix",
        )
    except OSError as cause:
        return err(
            AnalysisCapabilityUnavailableError(
                message=f"could not launch Electron: {cause}",
                provider_id=_PROVIDER.id,
                operation="capture_electron_scenario",
                reason="provider_unavailable",
            )
        )
    endpoint = f"http://127.0.0.1:{port}"
    timeout = float(parameters.get("launch_timeout") or 20.0)
    deadline = time.monotonic() + max(1.0, timeout)
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            _stop_electron(process)
            return err(
                AnalysisCapabilityUnavailableError(
                    message=f"Electron exited before exposing CDP (code {process.returncode})",
                    provider_id=_PROVIDER.id,
                    operation="capture_electron_scenario",
                    reason="provider_unavailable",
                )
            )
        try:
            _http_json(f"{endpoint}/json/version", timeout=1.0)
            return ok(
                (
                    process,
                    endpoint,
                    {
                        "executable": executable,
                        "app": app,
                        "pid": process.pid,
                        "port": port,
                        "arguments": arguments[1:],
                    },
                )
            )
        except (urllib.error.URLError, ValueError, OSError) as cause:
            last_error = cause
            time.sleep(0.2)
    _stop_electron(process)
    return err(
        AnalysisCapabilityUnavailableError(
            message=f"Electron did not expose CDP within {timeout:.0f}s: {last_error}",
            provider_id=_PROVIDER.id,
            operation="capture_electron_scenario",
            reason="provider_unavailable",
        )
    )


def _stop_electron(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        killpg = getattr(os, "killpg", None)
        if os.name == "posix" and killpg is not None:
            killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=5)
        else:
            process.terminate()
            process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        try:
            if os.name == "posix" and killpg is not None:
                killpg(process.pid, getattr(signal, "SIGKILL", signal.SIGTERM))
            else:
                process.kill()
        except OSError:
            pass
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=2)


def _targets(parameters: dict[str, Any]) -> list[dict[str, Any]]:
    payload = _http_json(f"{_endpoint(parameters)}/json/list")
    return [item for item in payload if isinstance(item, dict)] if isinstance(payload, list) else []


_WEBMCP_INIT_SCRIPT = """
(() => {
  window.__reaWebmcpTools = [];
  window.__reaWebmcpHandlers = window.__reaWebmcpHandlers || {};
  let context = typeof navigator !== 'undefined' ? navigator.modelContext : null;
  if (!context && typeof navigator !== 'undefined') {
    context = {};
    try { Object.defineProperty(navigator, 'modelContext', { value: context, configurable: true }); } catch (_) { return; }
  }
  if (!context) return;
  for (const method of ['registerTool', 'defineTool']) {
    if (typeof context[method] !== 'function') context[method] = function () {};
    const original = context[method];
    context[method] = function(tool) {
      try {
        const name = tool && (tool.name || tool.title) || null;
        window.__reaWebmcpTools.push({
          name,
          description: tool && tool.description || null,
          inputSchema: tool && tool.inputSchema || null,
          method,
        });
        if (name) window.__reaWebmcpHandlers[name] = tool;
      } catch (_) {}
      return original.apply(this, arguments);
    };
  }
})();
"""


class WebRuntimeProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def _playwright_available(self) -> tuple[bool, str | None]:
        if optional_import("playwright") is None:
            return False, "the optional 'playwright' package is not installed"
        return True, None

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        available, reason = self._playwright_available()
        descriptors = []
        for operation in _OPERATIONS:
            descriptors.append(
                CapabilityDescriptor(
                    operation=operation,
                    provider=_PROVIDER,
                    available=available,
                    reason=reason,
                    effects=CapabilityEffects(
                        launches_process=operation not in _CDP_OPERATIONS,
                        may_access_network=True,
                        may_write_filesystem=operation
                        in (
                            "capture_web_screenshot",
                            "export_web_scripts",
                            "recover_javascript_sources",
                        ),
                    ),
                    limitations=("Requires the caller's browser/automation stack.",),
                )
            )
        return tuple(descriptors)

    def supports(self, target: BinaryTarget) -> TargetSupport:
        return TargetSupport("supported")

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del profile
        if operation not in _OPERATIONS:
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        if operation == "trace_native_ui_action":
            return err(
                AnalysisCapabilityUnavailableError(
                    message="native UI action tracing requires a platform UI bridge",
                    provider_id=_PROVIDER.id,
                    operation=operation,
                    reason="provider_unavailable",
                    remediation_action="Use the CDP/Electron observation tools instead.",
                )
            )
        if operation in _CDP_OPERATIONS:
            return self._cdp(operation, parameters)
        if operation in ("analyze_web_bundle", "compare_web_screenshots"):
            local_handler: (
                Callable[[BinaryTarget, dict[str, Any]], Result[AnalysisExecution, AnalysisError]]
                | None
            ) = getattr(self, f"_op_{operation}", None)
            if local_handler is None:
                return err(
                    AnalysisInputError(
                        operation=operation, message=f"unsupported operation {operation}"
                    )
                )
            return local_handler(target, parameters)
        available, reason = self._playwright_available()
        if not available:
            return err(
                AnalysisCapabilityUnavailableError(
                    message=reason or "playwright is unavailable",
                    provider_id=_PROVIDER.id,
                    operation=operation,
                    reason="provider_unavailable",
                    remediation_action="Install playwright and a Chrome-family browser.",
                )
            )
        handler: (
            Callable[[BinaryTarget, dict[str, Any]], Result[AnalysisExecution, AnalysisError]]
            | None
        ) = getattr(self, f"_op_{operation}", None)
        if handler is None:
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        return handler(target, parameters)

    # -- CDP-only ----------------------------------------------------------

    def _cdp(
        self, operation: str, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        if operation == "capture_electron_scenario" and parameters.get("app"):
            launched = _launch_electron(parameters)
            if not launched.ok:
                return err(launched.error)
            process, launched_endpoint, launch = launched.value
            scoped = {**parameters, "endpoint": launched_endpoint}
            try:
                result = self._scenario_over_cdp(launched_endpoint, scoped, operation)
                if result.ok and isinstance(result.value.result, dict):
                    result.value.result["launch"] = launch
                return result
            finally:
                _stop_electron(process)
        endpoint = _endpoint(parameters)
        try:
            targets = _targets(parameters)
        except (urllib.error.URLError, ValueError, OSError) as cause:
            return err(
                AnalysisCapabilityUnavailableError(
                    message=f"no CDP endpoint at {endpoint}: {cause}",
                    provider_id=_PROVIDER.id,
                    operation=operation,
                    reason="provider_unavailable",
                    remediation_action="Start the runtime with --remote-debugging-port.",
                )
            )
        pages = [item for item in targets if item.get("type") in (None, "page")]
        if operation == "inspect_electron_page":
            page = pages[0] if pages else None
            return ok(
                AnalysisExecution(
                    result={"endpoint": endpoint, "page": page},
                    provider=self.identity(),
                )
            )
        if operation == "observe_javascript_runtime":
            return ok(
                AnalysisExecution(
                    result={"endpoint": endpoint, "targets": pages},
                    provider=self.identity(),
                    limitations=("Target inventory only; no expression evaluation.",),
                )
            )
        if operation == "reconcile_javascript_runtime":
            left = str(parameters.get("left") or "")
            right = str(parameters.get("right") or "")
            left_targets = _read_target_list(left) if left else pages
            right_targets = _read_target_list(right) if right else pages
            left_urls = {str(item.get("url")) for item in left_targets}
            right_urls = {str(item.get("url")) for item in right_targets}
            return ok(
                AnalysisExecution(
                    result={
                        "added": sorted(right_urls - left_urls),
                        "removed": sorted(left_urls - right_urls),
                        "shared": sorted(left_urls & right_urls),
                    },
                    provider=self.identity(),
                )
            )
        if operation in ("list_electron_targets", "list_javascript_runtime_targets"):
            kind = "worker" if operation == "list_javascript_runtime_targets" else "page"
            selected = [
                item
                for item in targets
                if item.get("type") in (kind, "page", "service_worker", "shared_worker")
            ]
            return ok(
                AnalysisExecution(
                    result={
                        "endpoint": endpoint,
                        "targets": selected,
                        "target_count": len(selected),
                    },
                    provider=self.identity(),
                )
            )
        if operation == "capture_electron_scenario":
            return self._scenario_over_cdp(endpoint, parameters, operation)
        return ok(
            AnalysisExecution(
                result={"endpoint": endpoint, "targets": targets, "target_count": len(targets)},
                provider=self.identity(),
            )
        )

    def _scenario_over_cdp(
        self, endpoint: str, parameters: dict[str, Any], operation: str
    ) -> Result[AnalysisExecution, AnalysisError]:
        pw_available, reason = self._playwright_available()
        if not pw_available:
            return err(
                AnalysisCapabilityUnavailableError(
                    message=reason or "playwright is unavailable",
                    provider_id=_PROVIDER.id,
                    operation=operation,
                    reason="provider_unavailable",
                    remediation_action="Install playwright.",
                )
            )
        from playwright.sync_api import sync_playwright

        steps = parameters.get("steps") or []
        results: list[Any] = []
        with sync_playwright() as playwright:
            browser = playwright.chromium.connect_over_cdp(endpoint)
            context = browser.contexts[0] if browser.contexts else browser.new_context()
            page = context.pages[0] if context.pages else context.new_page()
            try:
                results = _run_steps(page, steps)
            finally:
                browser.close()
        return ok(
            AnalysisExecution(
                result={"endpoint": endpoint, "steps": results}, provider=self.identity()
            )
        )

    # -- Playwright operations --------------------------------------------

    def _new_page(self) -> tuple[Any, Any, Any]:
        from playwright.sync_api import sync_playwright

        playwright = sync_playwright().start()
        executable = os.environ.get("REA_BROWSER_EXECUTABLE")
        browser = (
            playwright.chromium.launch(executable_path=executable)
            if executable
            else playwright.chromium.launch()
        )
        page = browser.new_page()
        return playwright, browser, page

    def _op_inspect_web_page(self, target: BinaryTarget, parameters: dict[str, Any]) -> Any:
        del target
        url = parameters.get("url")
        if not url:
            return err(AnalysisInputError(operation="inspect_web_page", message="url is required"))
        playwright, browser, page = self._new_page()
        try:
            page.goto(str(url), wait_until="domcontentloaded")
            result = {
                "url": page.url,
                "title": page.title(),
                "script_count": page.eval_on_selector_all("script", "els => els.length"),
                "form_count": page.eval_on_selector_all("form", "els => els.length"),
                "link_count": page.eval_on_selector_all("a", "els => els.length"),
                "meta": page.eval_on_selector_all(
                    "meta",
                    "els => els.map(e => ({name: e.getAttribute('name'), property: e.getAttribute('property'), content: e.getAttribute('content')}))",
                ),
            }
        finally:
            browser.close()
            playwright.stop()
        return ok(AnalysisExecution(result=result, provider=self.identity()))

    def _op_inspect_web_event_listeners(
        self, target: BinaryTarget, parameters: dict[str, Any]
    ) -> Any:
        del target
        url = parameters.get("url")
        if not url:
            return err(
                AnalysisInputError(
                    operation="inspect_web_event_listeners", message="url is required"
                )
            )
        selector = str(parameters.get("selector") or "body")
        playwright, browser, page = self._new_page()
        scripts: dict[str, str] = {}
        source_error: str | None = None
        listeners: list[dict[str, Any]] = []
        try:
            context = page.context
            cdp = context.new_cdp_session(page)

            def on_script(event: dict[str, Any]) -> None:
                scripts[str(event.get("scriptId"))] = str(event.get("url") or "")

            cdp.on("Debugger.scriptParsed", on_script)
            cdp.send("Debugger.enable")
            cdp.send("DOM.enable")
            page.goto(str(url), wait_until="domcontentloaded")
            page.wait_for_timeout(100)
            inline = page.eval_on_selector_all(
                "*",
                "els => els.flatMap(e => Array.from(e.attributes||[]).filter(a => a.name.startsWith('on')).map(a => ({tag: e.tagName, attribute: a.name, value: a.value})))",
            )
            inline_scripts = page.eval_on_selector_all(
                "script",
                "els => els.map(e => e.textContent || '').filter(Boolean)",
            )
            registrations = [
                {"script_index": index, "occurrences": text.count("addEventListener")}
                for index, text in enumerate(inline_scripts)
                if "addEventListener" in text
            ]
            try:
                document = cdp.send("DOM.getDocument", {"depth": 0})
                matches = cdp.send(
                    "DOM.querySelectorAll",
                    {"nodeId": document["root"]["nodeId"], "selector": selector},
                )
                node_ids = matches.get("nodeIds") or []
                if node_ids:
                    resolved = cdp.send("DOM.resolveNode", {"nodeId": node_ids[0]})
                    object_id = resolved.get("object", {}).get("objectId")
                    if object_id:
                        payload = cdp.send(
                            "DOMDebugger.getEventListeners",
                            {"objectId": object_id, "depth": 1, "pierce": True},
                        )
                        for listener in (payload.get("listeners") or [])[:200]:
                            script_id = str(listener.get("scriptId") or "")
                            line = int(listener.get("lineNumber") or 0)
                            column = int(listener.get("columnNumber") or 0)
                            source_line = None
                            if script_id:
                                try:
                                    source = (
                                        cdp.send(
                                            "Debugger.getScriptSource", {"scriptId": script_id}
                                        ).get("scriptSource")
                                        or ""
                                    )
                                    lines = source.splitlines()
                                    if lines:
                                        source_line = lines[min(max(line, 0), len(lines) - 1)][
                                            :1000
                                        ]
                                except Exception:
                                    source_line = None
                            listeners.append(
                                {
                                    "type": listener.get("type"),
                                    "use_capture": bool(listener.get("useCapture")),
                                    "passive": bool(listener.get("passive")),
                                    "once": bool(listener.get("once")),
                                    "script_id": script_id or None,
                                    "script_url": scripts.get(script_id) or None,
                                    "line": line + 1 if script_id else None,
                                    "column": column,
                                    "source_line": source_line,
                                    "handler": (listener.get("handler") or {}).get("description"),
                                    "selector": selector,
                                    "frame_url": page.url,
                                }
                            )
            except Exception as cause:
                source_error = str(cause)
        finally:
            browser.close()
            playwright.stop()
        return ok(
            AnalysisExecution(
                result={
                    "url": url,
                    "selector": selector,
                    "inline_handlers": inline,
                    "add_event_listener": registrations,
                    "listeners": listeners,
                    "listener_count": len(listeners),
                    "source_location_error": source_error,
                },
                provider=self.identity(),
                limitations=(
                    "Listener ownership is limited to the first matching main-document element.",
                    "Listener source locations come from the page debugger and may be unavailable for native or workers.",
                ),
            )
        )

    def _op_observe_web_execution(self, target: BinaryTarget, parameters: dict[str, Any]) -> Any:
        del target
        url = parameters.get("url")
        if not url:
            return err(
                AnalysisInputError(operation="observe_web_execution", message="url is required")
            )
        duration = min(float(parameters.get("duration") or 3.0), 300.0)
        capture_bodies = bool(parameters.get("capture_bodies"))
        retain_bodies = bool(parameters.get("retain_bodies"))
        playwright, browser, page = self._new_page()
        console: list[Any] = []
        requests: list[Any] = []
        pending: list[tuple[dict[str, Any], Any]] = []
        page.on(
            "console", lambda message: console.append({"type": message.type, "text": message.text})
        )
        page.on(
            "request",
            lambda request: requests.append({"method": request.method, "url": request.url}),
        )

        def on_response(response: Any) -> None:
            try:
                request = response.request
                if request.resource_type not in ("xhr", "fetch") or len(pending) >= 200:
                    return
                pending.append(
                    (
                        {
                            "url": response.url,
                            "status": response.status,
                            "resource_type": request.resource_type,
                        },
                        response,
                    )
                )
            except Exception:
                return

        page.on("response", on_response)
        responses: list[dict[str, Any]] = []
        retained_bodies: list[dict[str, Any]] = []
        total_body_bytes = 0
        retained_body_bytes = 0
        bodies_truncated = False
        retained_bodies_truncated = False
        try:
            page.goto(str(url), wait_until="domcontentloaded")
            page.wait_for_timeout(int(duration * 1000))
            page.wait_for_timeout(100)
            for entry, response in pending[:100]:
                if capture_bodies:
                    try:
                        text = response.text()
                    except Exception as cause:
                        entry["body_error"] = str(cause)
                    else:
                        remaining = _MAX_TOTAL_BODY_BYTES - total_body_bytes
                        limit = min(_MAX_BODY_BYTES, max(0, remaining))
                        entry["body"] = text[:limit]
                        entry["body_truncated"] = len(text) > limit
                        total_body_bytes += len(entry["body"])
                        if len(text) > limit:
                            bodies_truncated = True
                        if retain_bodies:
                            capacity = _MAX_RETAINED_BODY_BYTES - retained_body_bytes
                            if capacity <= 0:
                                retained_bodies_truncated = True
                            else:
                                body = text[:capacity]
                                retained_bodies.append(
                                    {
                                        "url": entry["url"],
                                        "status": entry["status"],
                                        "body": body,
                                    }
                                )
                                retained_body_bytes += len(body)
                                if len(text) > capacity:
                                    retained_bodies_truncated = True
                responses.append(entry)
        finally:
            browser.close()
            playwright.stop()
        return ok(
            AnalysisExecution(
                result={
                    "url": url,
                    "console": console[:1000],
                    "requests": requests[:1000],
                    "responses": responses,
                    "console_count": len(console),
                    "request_count": len(requests),
                    "response_count": len(responses),
                    "bodies_captured": capture_bodies,
                    "body_bytes_total": total_body_bytes,
                    "bodies_truncated": bodies_truncated,
                    "retain_bodies": retain_bodies,
                    "retained_body_bytes": retained_body_bytes,
                    "retained_bodies_truncated": retained_bodies_truncated,
                    **({"retained_bodies": retained_bodies} if retain_bodies else {}),
                },
                provider=self.identity(),
            )
        )

    def _op_observe_web_session(self, target: BinaryTarget, parameters: dict[str, Any]) -> Any:
        del target
        url = parameters.get("url")
        if not url:
            return err(
                AnalysisInputError(operation="observe_web_session", message="url is required")
            )
        playwright, browser, page = self._new_page()
        try:
            page.goto(str(url), wait_until="domcontentloaded")
            cookies = page.context.cookies()
            storage = page.evaluate(
                "() => ({local: Object.keys(localStorage), session: Object.keys(sessionStorage)})"
            )
            title = page.title()
        finally:
            browser.close()
            playwright.stop()
        return ok(
            AnalysisExecution(
                result={"url": url, "title": title, "cookies": cookies, "storage": storage},
                provider=self.identity(),
            )
        )

    def _op_capture_web_screenshot(self, target: BinaryTarget, parameters: dict[str, Any]) -> Any:
        del target
        url = parameters.get("url")
        output = parameters.get("output")
        if not url or not output:
            return err(
                AnalysisInputError(
                    operation="capture_web_screenshot", message="url and output are required"
                )
            )
        destination = Path(str(output)).expanduser()
        if destination.exists():
            return err(
                AnalysisInputError(
                    operation="capture_web_screenshot",
                    message=f"output already exists: {destination}",
                )
            )
        destination.parent.mkdir(parents=True, exist_ok=True)
        playwright, browser, page = self._new_page()
        try:
            page.goto(str(url), wait_until="domcontentloaded")
            page.screenshot(path=str(destination), full_page=bool(parameters.get("full_page")))
        finally:
            browser.close()
            playwright.stop()
        return ok(
            AnalysisExecution(
                result={
                    "url": url,
                    "path": str(destination),
                    "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
                    "size": destination.stat().st_size,
                },
                provider=self.identity(),
            )
        )

    def _op_compare_web_screenshots(self, target: BinaryTarget, parameters: dict[str, Any]) -> Any:
        del target
        left = parameters.get("left")
        right = parameters.get("right")
        if not left or not right:
            return err(
                AnalysisInputError(
                    operation="compare_web_screenshots", message="left and right are required"
                )
            )
        left_bytes = Path(str(left)).read_bytes()
        right_bytes = Path(str(right)).read_bytes()
        left_hash = hashlib.sha256(left_bytes).hexdigest()
        right_hash = hashlib.sha256(right_bytes).hexdigest()
        return ok(
            AnalysisExecution(
                result={
                    "status": "unchanged" if left_hash == right_hash else "changed",
                    "left": {"sha256": left_hash, "size": len(left_bytes)},
                    "right": {"sha256": right_hash, "size": len(right_bytes)},
                },
                provider=self.identity(),
            )
        )

    def _op_capture_browser_scenario(self, target: BinaryTarget, parameters: dict[str, Any]) -> Any:
        del target
        playwright, browser, page = self._new_page()
        try:
            results = _run_steps(page, parameters.get("steps") or [])
        finally:
            browser.close()
            playwright.stop()
        return ok(AnalysisExecution(result={"steps": results}, provider=self.identity()))

    def _op_export_web_scripts(self, target: BinaryTarget, parameters: dict[str, Any]) -> Any:
        del target
        url = parameters.get("url")
        output = parameters.get("output")
        if not url or not output:
            return err(
                AnalysisInputError(
                    operation="export_web_scripts", message="url and output are required"
                )
            )
        out_dir = Path(str(output)).expanduser()
        out_dir.mkdir(parents=True, exist_ok=True)
        playwright, browser, page = self._new_page()
        try:
            page.goto(str(url), wait_until="domcontentloaded")
            sources = page.eval_on_selector_all("script[src]", "els => els.map(e => e.src)")
            exported = []
            for index, source in enumerate(sources):
                try:
                    response = page.request.get(str(source))
                    if not response.ok:
                        continue
                    destination = out_dir / f"script_{index:03d}.js"
                    destination.write_text(response.text(), encoding="utf-8")
                    exported.append({"url": source, "path": str(destination)})
                except Exception:
                    continue
        finally:
            browser.close()
            playwright.stop()
        return ok(
            AnalysisExecution(
                result={"url": url, "exported": exported, "exported_count": len(exported)},
                provider=self.identity(),
            )
        )

    def _op_recover_javascript_sources(
        self, target: BinaryTarget, parameters: dict[str, Any]
    ) -> Any:
        del target
        url = parameters.get("url")
        output = parameters.get("output")
        if not url or not output:
            return err(
                AnalysisInputError(
                    operation="recover_javascript_sources", message="url and output are required"
                )
            )
        out_dir = Path(str(output)).expanduser()
        out_dir.mkdir(parents=True, exist_ok=True)
        playwright, browser, page = self._new_page()
        recovered: list[Any] = []
        try:
            page.goto(str(url), wait_until="domcontentloaded")
            sources = page.eval_on_selector_all("script[src]", "els => els.map(e => e.src)")
            for index, source in enumerate(sources):
                try:
                    text = page.request.get(str(source)).text()
                except Exception:
                    continue
                match = re.search(r"//# sourceMappingURL=(\S+)", text)
                if not match:
                    continue
                map_url = urllib.parse.urljoin(str(source), match.group(1))
                try:
                    mapping = json.loads(page.request.get(map_url).text())
                except Exception:
                    continue
                for name, content in zip(
                    mapping.get("sources", []),
                    mapping.get("sourcesContent", []),
                    strict=False,
                ):
                    if content is None:
                        continue
                    destination = out_dir / f"source_{index:03d}_{Path(str(name)).name}"
                    destination.write_text(content, encoding="utf-8")
                    recovered.append({"name": name, "path": str(destination)})
        finally:
            browser.close()
            playwright.stop()
        return ok(
            AnalysisExecution(
                result={"url": url, "sources": recovered, "source_count": len(recovered)},
                provider=self.identity(),
            )
        )

    def _op_trace_web_module_imports(self, target: BinaryTarget, parameters: dict[str, Any]) -> Any:
        del target
        url = parameters.get("url")
        if not url:
            return err(
                AnalysisInputError(operation="trace_web_module_imports", message="url is required")
            )
        playwright, browser, page = self._new_page()
        edges: list[dict[str, Any]] = []
        try:
            page.goto(str(url), wait_until="domcontentloaded")
            sources = page.eval_on_selector_all("script[src]", "els => els.map(e => e.src)")
            for source in sources:
                try:
                    text = page.request.get(str(source)).text()
                except Exception:
                    continue
                for module in _SCRIPT_RE.findall(text):
                    edges.append({"from": str(source), "module": module})
        finally:
            browser.close()
            playwright.stop()
        return ok(
            AnalysisExecution(
                result={"url": url, "edges": edges, "edge_count": len(edges)},
                provider=self.identity(),
            )
        )

    def _op_trace_web_source_location(
        self, target: BinaryTarget, parameters: dict[str, Any]
    ) -> Any:
        del target
        source_url = parameters.get("source_url")
        symbol = parameters.get("symbol") or parameters.get("query")
        if not source_url or not symbol:
            return err(
                AnalysisInputError(
                    operation="trace_web_source_location",
                    message="source_url and symbol are required",
                )
            )
        playwright, browser, page = self._new_page()
        try:
            text = page.request.get(str(source_url)).text()
        finally:
            browser.close()
            playwright.stop()
        matches = [
            {"line": number, "text": line.strip()[:500]}
            for number, line in enumerate(text.splitlines(), start=1)
            if str(symbol) in line
        ]
        return ok(
            AnalysisExecution(
                result={"source_url": source_url, "symbol": symbol, "matches": matches[:200]},
                provider=self.identity(),
            )
        )

    def _op_discover_webmcp_tools(self, target: BinaryTarget, parameters: dict[str, Any]) -> Any:
        del target
        url = parameters.get("url")
        if not url:
            return err(
                AnalysisInputError(operation="discover_webmcp_tools", message="url is required")
            )
        playwright, browser, page = self._new_page()
        try:
            page.add_init_script(_WEBMCP_INIT_SCRIPT)
            page.goto(str(url), wait_until="domcontentloaded")
            declared = page.evaluate(
                "() => ({modelContext: typeof navigator !== 'undefined' && !!navigator.modelContext, markers: Array.from(document.querySelectorAll('[data-webmcp], [data-mcp-tool]')).map(e => ({tag: e.tagName, name: e.getAttribute('data-mcp-tool') || e.getAttribute('name')})), registered_tools: window.__reaWebmcpTools || []})"
            )
        finally:
            browser.close()
            playwright.stop()
        registered = declared.get("registered_tools") or []
        return ok(
            AnalysisExecution(
                result={
                    "url": url,
                    **declared,
                    "tool_count": len(registered),
                    "limitations": [
                        "Only registrations that occur after the page starts and before the observation ends are captured."
                    ]
                    if registered
                    else [],
                },
                provider=self.identity(),
            )
        )

    def _op_invoke_webmcp_tool(self, target: BinaryTarget, parameters: dict[str, Any]) -> Any:
        del target
        url = parameters.get("url")
        name = parameters.get("name") or parameters.get("tool")
        arguments = parameters.get("arguments") or {}
        if not url or not name:
            return err(
                AnalysisInputError(
                    operation="invoke_webmcp_tool", message="url and name are required"
                )
            )
        if not isinstance(arguments, dict):
            return err(
                AnalysisInputError(
                    operation="invoke_webmcp_tool", message="arguments must be an object"
                )
            )
        try:
            import json as _json

            encoded = _json.dumps(arguments)
        except (TypeError, ValueError) as cause:
            return err(AnalysisInputError(operation="invoke_webmcp_tool", message=str(cause)))
        playwright, browser, page = self._new_page()
        try:
            page.add_init_script(_WEBMCP_INIT_SCRIPT)
            page.goto(str(url), wait_until="domcontentloaded")
            outcome = page.evaluate(
                """async ({name, encoded}) => {
                  const tool = window.__reaWebmcpHandlers && window.__reaWebmcpHandlers[name];
                  if (!tool) return {status: 'unknown', error: 'tool not registered'};
                  const fn = tool.execute || tool.handler || tool.invoke || tool.run;
                  if (typeof fn !== 'function') return {status: 'unknown', error: 'tool has no executable handler'};
                  try {
                    const value = await fn.call(tool, JSON.parse(encoded));
                    return {status: 'called', result: value};
                  } catch (error) {
                    return {status: 'error', error: String(error && error.message || error)};
                  }
                }""",
                {"name": str(name), "encoded": encoded},
            )
        finally:
            browser.close()
            playwright.stop()
        return ok(
            AnalysisExecution(
                result={
                    "url": url,
                    "name": name,
                    "arguments": arguments,
                    **outcome,
                    "limitations": (
                        "This explicitly executes the page's registered WebMCP handler; target behavior is not otherwise analyzed."
                    ),
                },
                provider=self.identity(),
            )
        )

    def _op_analyze_web_bundle(self, target: BinaryTarget, parameters: dict[str, Any]) -> Any:
        path = parameters.get("path") or target.path
        source = Path(str(path))
        if not source.exists():
            return err(
                AnalysisInputError(operation="analyze_web_bundle", message=f"not found: {path}")
            )
        files = [source] if source.is_file() else sorted(source.rglob("*.js"))
        imports: list[dict[str, Any]] = []
        total = 0
        for file in files[:500]:
            try:
                text = file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            total += len(text)
            for module in _SCRIPT_RE.findall(text):
                imports.append({"from": file.as_posix(), "module": module})
        return ok(
            AnalysisExecution(
                result={
                    "root": source.as_posix(),
                    "file_count": len(files),
                    "total_bytes": total,
                    "imports": imports[:2000],
                    "import_count": len(imports),
                },
                provider=self.identity(),
            )
        )


def _read_target_list(path: str) -> list[dict[str, Any]]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    items = payload.get("targets") if isinstance(payload, dict) else payload
    return [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []


def _run_steps(page: Any, steps: Any) -> list[Any]:
    results: list[Any] = []
    for step in steps if isinstance(steps, list) else []:
        if not isinstance(step, dict):
            continue
        action = step.get("action")
        if action == "goto":
            page.goto(str(step.get("url")), wait_until="domcontentloaded")
        elif action == "click":
            page.click(str(step.get("selector")))
        elif action == "fill":
            page.fill(str(step.get("selector")), str(step.get("value") or ""))
        elif action == "wait":
            time.sleep(min(float(step.get("seconds") or 1.0), 60.0))
        elif action == "screenshot":
            page.screenshot(path=str(step.get("path")))
        results.append({"action": action, "ok": True})
    return results


__all__ = ["WebRuntimeProvider"]
