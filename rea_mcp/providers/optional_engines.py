"""Optional engines: Ghidra, Hopper, IDA, JEB, Frida, browser, recorded crash.

Availability depends on optional imports or caller-provided configuration; when
absent, operations report an actionable capability error. Attach-style engines
(Hopper, IDA, JEB) run only against a caller-started service.
"""

from __future__ import annotations

import os
import shlex
import urllib.error
import urllib.request

from ..domain.analysis_error import (
    AnalysisCapabilityUnavailableError,
    AnalysisError,
    AnalysisInputError,
)
from ..domain.analysis_profile import ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import err, ok
from ..process.supervision import run_owned_process
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .external import optional_import
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

    def _availability(self) -> tuple[bool, str | None]:
        if optional_import("pyhidra") is None:
            return False, "the optional 'pyhidra' package (with Ghidra + JDK) is not installed"
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
        import pyhidra

        pseudocode: str | None = None
        with pyhidra.open_program(target.path) as flat_api:
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


class _HttpMcpEngine(_OptionalEngine):
    env_var = "REA_MCP_URL"
    operation_name = "inspect_provider"

    def _url(self) -> str | None:
        return os.environ.get(self.env_var)

    def _availability(self) -> tuple[bool, str | None]:
        if not self._url():
            return False, f"set {self.env_var} to the running engine's MCP endpoint"
        return True, None

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        available, reason = self._availability()
        return (self._capability(self.operation_name, reason, available),)

    def analyze(self, operation, target, parameters, profile):  # type: ignore[no-untyped-def]
        del target, parameters, profile
        available, reason = self._availability()
        if not available:
            return err(self._unavailable(operation, reason or "endpoint not configured"))
        url = self._url()
        assert url is not None
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                status = response.status
        except (urllib.error.URLError, OSError) as cause:
            return err(self._unavailable(operation, f"endpoint {url} is unreachable: {cause}"))
        return ok(
            AnalysisExecution(
                result={"endpoint": url, "reachable": True, "status": status},
                provider=self.identity(),
                limitations=("Only endpoint reachability is verified in this build.",),
            )
        )


class IdaProvider(_HttpMcpEngine):
    provider_id = "ida"
    provider_name = "REA-Python IDA adapter"
    env_var = "REA_IDA_MCP_URL"
    operation_name = "ida_inspect_provider"


class JebProvider(_HttpMcpEngine):
    provider_id = "jeb"
    provider_name = "REA-Python JEB adapter"
    env_var = "REA_JEB_MCP_URL"
    operation_name = "jeb_inspect_provider"


class FridaProvider(_OptionalEngine):
    provider_id = "frida"
    provider_name = "REA-Python Frida instrumentation"

    def _availability(self) -> tuple[bool, str | None]:
        if optional_import("frida") is None:
            return False, "the optional 'frida' package is not installed"
        return True, None

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        available, reason = self._availability()
        return (self._capability("list_frida_devices", reason, available),)

    def supports(self, target: BinaryTarget) -> TargetSupport:
        return TargetSupport("supported")

    def analyze(self, operation, target, parameters, profile):  # type: ignore[no-untyped-def]
        del target, parameters, profile
        available, reason = self._availability()
        if not available:
            return err(self._unavailable(operation, reason or "Frida unavailable"))
        import frida

        devices = [
            {"id": device.id, "name": device.name, "type": device.type}
            for device in frida.get_device_manager().enumerate_devices()
        ]
        return ok(AnalysisExecution(result={"devices": devices}, provider=self.identity()))


class BrowserProvider(_OptionalEngine):
    provider_id = "browser"
    provider_name = "REA-Python browser observation"

    def _availability(self) -> tuple[bool, str | None]:
        if optional_import("playwright") is None:
            return False, "the optional 'playwright' package is not installed"
        if not os.environ.get("REA_BROWSER_EXECUTABLE"):
            return False, "set REA_BROWSER_EXECUTABLE to a Chrome-family browser"
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

        executable = os.environ["REA_BROWSER_EXECUTABLE"]
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=executable)
            page = browser.new_page()
            page.goto(str(url))
            title = page.title()
            script_count = len(page.eval_on_selector_all("script", "els => els.length"))
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
