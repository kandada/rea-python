"""Optional engines: Ghidra, Hopper, IDA, JEB, Frida, browser, recorded crash.

Availability depends on optional imports or caller-provided configuration; when
absent, operations report an actionable capability error. Attach-style engines
(Hopper, IDA, JEB) run only against a caller-started service.
"""

from __future__ import annotations

import contextlib
import os
import re
import shlex
from typing import Any

from ..domain.analysis_error import (
    AnalysisCapabilityUnavailableError,
    AnalysisError,
    AnalysisInputError,
    ProviderAdapterError,
)
from ..domain.analysis_profile import ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import err, ok
from ..process.supervision import run_owned_process
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .external import optional_import
from .mcp_client import (
    McpClient,
    McpClientError,
    McpServerConfig,
    jeb_reachable,
    load_ida_config,
    load_jeb_config,
)
from .registry import TargetSupport


class _OptionalEngine(AnalysisProvider):
    provider_id = "optional"
    provider_name = "REA-Python optional engine"

    def identity(self) -> ProviderIdentity:
        return ProviderIdentity(id=self.provider_id, name=self.provider_name, version="1")

    def _capability(
        self, operation: str, reason: str | None, available: bool
    ) -> CapabilityDescriptor:
        return CapabilityDescriptor(
            operation=operation,
            provider=self.identity(),
            available=available,
            reason=reason,
            effects=CapabilityEffects(launches_process=True),
        )

    def _unavailable(self, operation: str, reason: str) -> AnalysisError:
        return AnalysisCapabilityUnavailableError(
            message=reason,
            provider_id=self.provider_id,
            operation=operation,
            reason="provider_unavailable",
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format in ("elf", "pe", "mach-o", "mach-o-universal"):
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported", reason="requires a native binary", code="target_format_unsupported"
        )


class GhidraProvider(_OptionalEngine):
    provider_id = "ghidra"
    provider_name = "REA-Python Ghidra (pyhidra)"

    def _select_bridge(self) -> Any:
        override = os.environ.get("REA_GHIDRA_BRIDGE", "").lower()
        pyhidra = optional_import("pyhidra")
        pyghidra = optional_import("pyghidra")
        if override == "pyghidra":
            return pyghidra
        if override == "pyhidra":
            return pyhidra
        install = os.environ.get("GHIDRA_INSTALL_DIR", "")
        version = None
        match = re.search(r"ghidra_(\d+)\.(\d+)", install)
        if match:
            version = (int(match.group(1)), int(match.group(2)))
        if version is not None and version >= (11, 4) and pyghidra is not None:
            return pyghidra
        return pyhidra or pyghidra

    def _bridge_name(self) -> str | None:
        bridge = self._select_bridge()
        if bridge is None:
            return None
        return getattr(bridge, "__name__", "unknown")

    def _availability(self) -> tuple[bool, str | None]:
        bridge = self._select_bridge()
        if bridge is None:
            return False, (
                "install 'pyhidra' (Ghidra 11.3) or 'pyghidra' (Ghidra 11.4+) with Ghidra + JDK"
            )
        return True, None

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        available, reason = self._availability()
        return (
            self._capability("ghidra_analyze", reason, available),
            self._capability("ghidra_function", reason, available),
            self._capability("ghidra_decompile", reason, available),
        )

    def analyze(self, operation, target, parameters, profile):  # type: ignore[no-untyped-def]
        del profile
        available, reason = self._availability()
        if not available:
            return err(self._unavailable(operation, reason or "Ghidra unavailable"))
        if operation not in ("ghidra_analyze", "ghidra_function", "ghidra_decompile"):
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        bridge = self._select_bridge()
        assert bridge is not None
        pseudocode: str | None = None
        with bridge.open_program(target.path) as flat_api:
            program = flat_api.getCurrentProgram()
            language = program.getLanguageID().toString()
            functions = [fn.getName() for fn in program.getFunctionManager().getFunctions(True)]
            if operation == "ghidra_decompile":
                wanted = str(parameters.get("function", "main"))
                target_fn = flat_api.getFunction(wanted)
                if target_fn is None:
                    for fn in program.getFunctionManager().getFunctions(True):
                        if fn.getName() == wanted:
                            target_fn = fn
                            break
                if target_fn is not None:
                    import importlib

                    decompiler_module = importlib.import_module("ghidra.app.decompiler")
                    decompiler = decompiler_module.DecompInterface()
                    decompiler.openProgram(program)
                    outcome = decompiler.decompileFunction(target_fn, 60, None)
                    if outcome is not None and outcome.decompileCompleted():
                        pseudocode = outcome.getDecompiledFunction().getC()
        limit = int(parameters.get("limit", 200))
        return ok(
            AnalysisExecution(
                result={
                    "language": language,
                    "function_count": len(functions),
                    "functions": functions[:limit],
                    "function": parameters.get("function"),
                    "pseudocode": pseudocode,
                },
                provider=self.identity(),
            )
        )


class _McpEngine(_OptionalEngine):
    """Adapter for a caller-supplied MCP server (stdio or streamable HTTP)."""

    operations: tuple[str, ...] = ()
    timeout_env = "REA_IDA_MCP_TIMEOUT_MS"
    default_timeout_ms = 300_000

    def _load_config(self) -> McpServerConfig | None:
        raise NotImplementedError

    def _config(self) -> McpServerConfig | None:
        return self._load_config()

    def _availability(self) -> tuple[bool, str | None]:
        return (self._config() is not None, "MCP engine is not configured")

    def _timeout(self) -> float:
        raw = os.environ.get(self.timeout_env)
        if raw:
            try:
                return max(1.0, min(float(raw) / 1000.0, 3600.0))
            except ValueError:
                pass
        return self.default_timeout_ms / 1000.0

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        available, reason = self._availability()
        return tuple(
            self._capability(operation, reason, available) for operation in self.operations
        )

    def analyze(self, operation, target, parameters, profile):  # type: ignore[no-untyped-def]
        del profile
        if operation not in self.operations:
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        available, reason = self._availability()
        if not available:
            return err(self._unavailable(operation, reason or "MCP engine unavailable"))
        config = self._config()
        assert config is not None
        try:
            result = self._invoke(McpClient(config), operation, target, parameters)
        except McpClientError as cause:
            return err(ProviderAdapterError(message=f"upstream MCP engine failed: {cause}"))
        except Exception as cause:
            return err(ProviderAdapterError(message=f"upstream MCP transport failed: {cause}"))
        return ok(
            AnalysisExecution(
                result=result if isinstance(result, dict) else {"value": result},
                provider=self.identity(),
                limitations=("Analysis is produced by the caller's engine.",),
            )
        )

    def _invoke(
        self, client: McpClient, operation: str, target: BinaryTarget, parameters: dict[str, Any]
    ) -> Any:
        raise NotImplementedError


def _is_address(value: str) -> bool:
    return value.startswith(("0x", "0X")) or value.isdigit()


def _first_address(payload: Any) -> str | None:
    if isinstance(payload, dict):
        for key in ("functions", "results", "items", "matches", "data"):
            candidate = payload.get(key)
            if isinstance(candidate, list) and candidate:
                return _first_address(candidate)
        for key in ("address", "start", "ea", "offset"):
            if isinstance(payload.get(key), (str, int)):
                return str(payload[key])
        return None
    if isinstance(payload, list) and payload:
        return _first_address(payload[0])
    return None


class IdaProvider(_McpEngine):
    provider_id = "ida"
    provider_name = "REA-Python IDA adapter"
    timeout_env = "REA_IDA_MCP_TIMEOUT_MS"
    default_timeout_ms = 300_000
    operations = (
        "ida_inspect_provider",
        "ida_analyze",
        "ida_function",
        "ida_decompile",
        "ida_xrefs",
    )

    def _load_config(self) -> McpServerConfig | None:
        return load_ida_config()

    def _availability(self) -> tuple[bool, str | None]:
        if self._config() is None:
            return False, (
                "set REA_IDA_MCP_CONFIG to an IDA MCP registration JSON "
                "(or REA_IDA_MCP_URL / REA_IDA_MCP_COMMAND)"
            )
        return True, None

    def _invoke(
        self, client: McpClient, operation: str, target: BinaryTarget, parameters: dict[str, Any]
    ) -> Any:
        del target
        if operation in ("ida_inspect_provider", "ida_analyze"):
            return client.call("get_metadata", {}, timeout=self._timeout())
        if operation == "ida_function":
            function = str(parameters.get("function") or "main")
            if function != "main":
                return client.call("lookup_funcs", {"queries": [function]}, timeout=self._timeout())
            return client.call(
                "list_functions",
                {"offset": 0, "count": int(parameters.get("limit") or 200)},
                timeout=self._timeout(),
            )
        if operation == "ida_decompile":
            function = str(parameters.get("function") or "main")
            if _is_address(function):
                return client.call("decompile", {"addr": function}, timeout=self._timeout())
            lookup = client.call("lookup_funcs", {"queries": [function]}, timeout=self._timeout())
            address = _first_address(lookup)
            if address:
                return client.call(
                    "decompile_function", {"address": address}, timeout=self._timeout()
                )
            return lookup
        address = parameters.get("address") or parameters.get("function") or "main"
        return client.call("get_xrefs_to", {"address": str(address)}, timeout=self._timeout())


class JebProvider(_McpEngine):
    provider_id = "jeb"
    provider_name = "REA-Python JEB adapter"
    timeout_env = "REA_JEB_MCP_TIMEOUT_MS"
    default_timeout_ms = 900_000
    operations = (
        "jeb_inspect_provider",
        "inspect_jeb_client",
        "open_jeb_project",
        "list_jeb_units",
        "decompile_jeb_item",
        "jeb_analyze",
        "jeb_function",
        "jeb_decompile",
    )

    def _load_config(self) -> McpServerConfig | None:
        return load_jeb_config()

    def _availability(self) -> tuple[bool, str | None]:
        config = self._config()
        if config is None:
            return False, "set REA_JEB_MCP_URL to the running JEB MCP endpoint"
        if config.transport == "http" and not (
            os.environ.get("REA_JEB_MCP_URL") or jeb_reachable()
        ):
            return False, (
                f"no JEB MCP endpoint at {config.url}; start JEB's MCP server or set "
                "REA_JEB_MCP_URL"
            )
        return True, None

    def _invoke(
        self, client: McpClient, operation: str, target: BinaryTarget, parameters: dict[str, Any]
    ) -> Any:
        if operation in ("jeb_inspect_provider", "inspect_jeb_client", "jeb_analyze"):
            return client.call("get_client_information", {}, timeout=self._timeout())
        if operation == "open_jeb_project":
            return client.call("open_project", {"path": target.path}, timeout=self._timeout())
        if operation in ("list_jeb_units", "jeb_function"):
            return client.call("list_units", {}, timeout=self._timeout())
        item = parameters.get("item") or parameters.get("function") or ""
        return client.call("decompile_code_item", {"item": str(item)}, timeout=self._timeout())


_FRIDA_SESSIONS: dict[str, dict[str, Any]] = {}
_FRIDA_COUNTER = 0


class FridaProvider(_OptionalEngine):
    provider_id = "frida"
    provider_name = "REA-Python Frida instrumentation"

    def _availability(self) -> tuple[bool, str | None]:
        if optional_import("frida") is None:
            return False, "the optional 'frida' package is not installed"
        return True, None

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        available, reason = self._availability()
        return tuple(
            self._capability(operation, reason, available)
            for operation in (
                "list_frida_devices",
                "list_frida_applications",
                "list_frida_processes",
                "start_frida_session",
                "frida_session_status",
                "load_frida_script",
                "unload_frida_script",
                "resume_frida_session",
                "close_frida_session",
                "instrument_with_frida",
            )
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        return TargetSupport("supported")

    def analyze(self, operation, target, parameters, profile):  # type: ignore[no-untyped-def]
        del target, profile
        if operation not in {
            "list_frida_devices",
            "list_frida_applications",
            "list_frida_processes",
            "start_frida_session",
            "frida_session_status",
            "load_frida_script",
            "unload_frida_script",
            "resume_frida_session",
            "close_frida_session",
            "instrument_with_frida",
        }:
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        available, reason = self._availability()
        if not available:
            return err(self._unavailable(operation, reason or "Frida unavailable"))
        handler = getattr(self, f"_op_{operation}", None)
        assert handler is not None
        return handler(parameters)

    @staticmethod
    def _device(parameters: dict[str, Any]) -> Any:
        import frida

        device_id = parameters.get("device")
        if device_id:
            return frida.get_device(str(device_id))
        return frida.get_device_manager().enumerate_devices()[0]

    @staticmethod
    def _session(session_id: Any) -> dict[str, Any] | None:
        return _FRIDA_SESSIONS.get(str(session_id))

    def _op_list_frida_devices(self, parameters: dict[str, Any]) -> Any:
        del parameters
        import frida

        devices = [
            {"id": item.id, "name": item.name, "type": item.type}
            for item in frida.get_device_manager().enumerate_devices()
        ]
        return ok(AnalysisExecution(result={"devices": devices}, provider=self.identity()))

    def _op_list_frida_applications(self, parameters: dict[str, Any]) -> Any:
        device = self._device(parameters)
        applications = [
            {"identifier": app.identifier, "name": app.name, "pid": getattr(app, "pid", None)}
            for app in device.enumerate_applications()
        ]
        return ok(
            AnalysisExecution(
                result={"device": device.id, "applications": applications},
                provider=self.identity(),
            )
        )

    def _op_list_frida_processes(self, parameters: dict[str, Any]) -> Any:
        device = self._device(parameters)
        processes = [
            {"pid": process.pid, "name": process.name} for process in device.enumerate_processes()
        ]
        return ok(
            AnalysisExecution(
                result={"device": device.id, "processes": processes}, provider=self.identity()
            )
        )

    def _op_start_frida_session(self, parameters: dict[str, Any]) -> Any:
        global _FRIDA_COUNTER
        target = parameters.get("target")
        if target is None:
            return err(
                AnalysisInputError(
                    operation="start_frida_session", message="start_frida_session requires target"
                )
            )
        device = self._device(parameters)
        spawn = bool(parameters.get("spawn"))
        try:
            if spawn:
                pid = device.spawn([str(target)])
                session = device.attach(pid)
            else:
                if isinstance(target, int) or str(target).isdigit():
                    pid = int(target)
                    session = device.attach(pid)
                else:
                    process = device.get_process(str(target))
                    pid = process.pid
                    session = device.attach(pid)
        except Exception as cause:
            return err(
                AnalysisInputError(
                    operation="start_frida_session", message=f"attach failed: {cause}"
                )
            )
        _FRIDA_COUNTER += 1
        session_id = f"frida_{_FRIDA_COUNTER}"
        _FRIDA_SESSIONS[session_id] = {
            "device": device,
            "session": session,
            "pid": pid,
            "spawned": spawn,
            "scripts": {},
            "messages": [],
        }
        return ok(
            AnalysisExecution(
                result={"session_id": session_id, "pid": pid, "spawned": spawn},
                provider=self.identity(),
                limitations=("Caller-owned process; REA only attaches and scripts.",),
            )
        )

    def _op_frida_session_status(self, parameters: dict[str, Any]) -> Any:
        entry = self._session(parameters.get("session_id"))
        if entry is None:
            return err(
                AnalysisInputError(operation="frida_session_status", message="unknown session_id")
            )
        return ok(
            AnalysisExecution(
                result={
                    "session_id": parameters.get("session_id"),
                    "pid": entry["pid"],
                    "spawned": entry["spawned"],
                    "scripts": list(entry["scripts"]),
                    "message_count": len(entry["messages"]),
                },
                provider=self.identity(),
            )
        )

    def _op_load_frida_script(self, parameters: dict[str, Any]) -> Any:
        entry = self._session(parameters.get("session_id"))
        if entry is None:
            return err(
                AnalysisInputError(operation="load_frida_script", message="unknown session_id")
            )
        source = parameters.get("source")
        if not source:
            return err(
                AnalysisInputError(operation="load_frida_script", message="source is required")
            )
        name = str(parameters.get("name") or f"script_{len(entry['scripts']) + 1}")
        try:
            script = entry["session"].create_script(str(source))
            script.on("message", lambda message, data: entry["messages"].append(message))
            script.load()
        except Exception as cause:
            return err(
                AnalysisInputError(
                    operation="load_frida_script", message=f"script load failed: {cause}"
                )
            )
        entry["scripts"][name] = script
        return ok(
            AnalysisExecution(
                result={"session_id": parameters.get("session_id"), "script": name},
                provider=self.identity(),
            )
        )

    def _op_unload_frida_script(self, parameters: dict[str, Any]) -> Any:
        entry = self._session(parameters.get("session_id"))
        if entry is None:
            return err(
                AnalysisInputError(operation="unload_frida_script", message="unknown session_id")
            )
        name = str(parameters.get("name") or "")
        script = entry["scripts"].pop(name, None)
        if script is None:
            return err(
                AnalysisInputError(
                    operation="unload_frida_script", message=f"unknown script {name}"
                )
            )
        with contextlib.suppress(Exception):
            script.unload()
        return ok(
            AnalysisExecution(
                result={"session_id": parameters.get("session_id"), "unloaded": name},
                provider=self.identity(),
            )
        )

    def _op_resume_frida_session(self, parameters: dict[str, Any]) -> Any:
        entry = self._session(parameters.get("session_id"))
        if entry is None:
            return err(
                AnalysisInputError(operation="resume_frida_session", message="unknown session_id")
            )
        if entry["spawned"]:
            entry["device"].resume(entry["pid"])
            resumed = True
        else:
            resumed = False
        return ok(
            AnalysisExecution(
                result={"session_id": parameters.get("session_id"), "resumed": resumed},
                provider=self.identity(),
            )
        )

    def _op_close_frida_session(self, parameters: dict[str, Any]) -> Any:
        session_id = str(parameters.get("session_id"))
        entry = _FRIDA_SESSIONS.pop(session_id, None)
        if entry is None:
            return err(
                AnalysisInputError(operation="close_frida_session", message="unknown session_id")
            )
        for script in entry["scripts"].values():
            with contextlib.suppress(Exception):
                script.unload()
        with contextlib.suppress(Exception):
            entry["session"].detach()
        return ok(
            AnalysisExecution(
                result={"session_id": session_id, "closed": True}, provider=self.identity()
            )
        )

    def _op_instrument_with_frida(self, parameters: dict[str, Any]) -> Any:
        import time

        started = self._op_start_frida_session(parameters)
        if not started.ok:
            return started
        session_id = started.value.result["session_id"]
        loaded = self._op_load_frida_script(
            {"session_id": session_id, "source": parameters.get("source"), "name": "instrument"}
        )
        if not loaded.ok:
            self._op_close_frida_session({"session_id": session_id})
            return loaded
        try:
            time.sleep(min(float(parameters.get("duration") or 2.0), 600.0))
            entry = _FRIDA_SESSIONS.get(session_id)
            messages = list(entry["messages"]) if entry else []
        finally:
            self._op_close_frida_session({"session_id": session_id})
        return ok(
            AnalysisExecution(
                result={
                    "session_id": session_id,
                    "message_count": len(messages),
                    "messages": messages[:1000],
                },
                provider=self.identity(),
                limitations=("Collects script messages for the requested duration only.",),
            )
        )


class BrowserProvider(_OptionalEngine):
    provider_id = "browser"
    provider_name = "REA-Python browser observation"

    def _availability(self) -> tuple[bool, str | None]:
        if optional_import("playwright") is None:
            return False, "the optional 'playwright' package is not installed"
        return True, None

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        available, reason = self._availability()
        return (self._capability("observe_web_page", reason, available),)

    def supports(self, target: BinaryTarget) -> TargetSupport:
        return TargetSupport("supported")

    def analyze(self, operation, target, parameters, profile):  # type: ignore[no-untyped-def]
        del target, profile
        available, reason = self._availability()
        if not available:
            return err(self._unavailable(operation, reason or "browser unavailable"))
        url = parameters.get("url")
        if not url:
            return err(
                AnalysisInputError(operation=operation, message="observe_web_page requires a url")
            )
        from playwright.sync_api import sync_playwright

        executable = os.environ.get("REA_BROWSER_EXECUTABLE")
        with sync_playwright() as playwright:
            browser = (
                playwright.chromium.launch(executable_path=executable)
                if executable
                else playwright.chromium.launch()
            )
            page = browser.new_page()
            page.goto(str(url))
            title = page.title()
            script_count = int(page.eval_on_selector_all("script", "els => els.length"))
            final_url = page.url
            browser.close()
        return ok(
            AnalysisExecution(
                result={"url": final_url, "title": title, "script_count": script_count},
                provider=self.identity(),
            )
        )


class RecordedCrashProvider(_OptionalEngine):
    provider_id = "recorded-crash"
    provider_name = "REA-Python recorded crashes"

    def _availability(self) -> tuple[bool, str | None]:
        if not os.environ.get("REA_PWNTOOLS_PYTHON"):
            return False, "set REA_PWNTOOLS_PYTHON to a Python interpreter with pwntools"
        return True, None

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        available, reason = self._availability()
        return (self._capability("inspect_recorded_crash", reason, available),)

    def supports(self, target: BinaryTarget) -> TargetSupport:
        return TargetSupport("supported")

    def analyze(self, operation, target, parameters, profile):  # type: ignore[no-untyped-def]
        del profile
        available, reason = self._availability()
        if not available:
            return err(self._unavailable(operation, reason or "pwntools unavailable"))
        executable = parameters.get("executable")
        if not executable:
            return err(
                AnalysisInputError(
                    operation=operation,
                    message="inspect_recorded_crash requires an executable path",
                )
            )
        python = os.environ["REA_PWNTOOLS_PYTHON"]
        script = (
            "import json,sys;from pwn import *;"
            "c=Core(sys.argv[1],exe=sys.argv[2]);"
            "print(json.dumps({'exe':sys.argv[2],'registers':{k:str(v) for k,v in c.registers.items()},"
            "'signal':getattr(c,'signal',None)}))"
        )
        argv = [*shlex.split(python), "-c", script, target.path, str(executable)]
        result = run_owned_process(argv, timeout=120, operation=operation)
        if not result.ok:
            return err(result.error)
        return ok(
            AnalysisExecution(
                result={
                    "core": target.path,
                    "executable": executable,
                    "stdout": result.value.stdout,
                },
                provider=self.identity(),
                limitations=("Register extraction depends on the caller's pwntools version.",),
            )
        )


__all__ = [
    "BrowserProvider",
    "FridaProvider",
    "GhidraProvider",
    "IdaProvider",
    "JebProvider",
    "RecordedCrashProvider",
]
