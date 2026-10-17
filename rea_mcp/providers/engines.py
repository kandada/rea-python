"""CLI-backed engine adapters (caller-supplied): apktool, adb, sigrok, Kuna.

Each adapter reports an actionable capability error when its tool is missing and
runs a bounded, owned subprocess only when the caller supplies the tool.
"""

from __future__ import annotations

import shlex
import shutil
import tempfile
from pathlib import Path

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
from .external import ToolResolution, resolve_shell_command, resolve_tool
from .registry import TargetSupport


class _CliEngine(AnalysisProvider):
    """Shared availability handling for a caller-supplied CLI engine."""

    provider_id = "cli-engine"
    provider_name = "REA-Python CLI engine"
    tool_names: tuple[str, ...] = ()
    env_var: str | None = None
    effects = CapabilityEffects(launches_process=True)

    def identity(self) -> ProviderIdentity:
        return ProviderIdentity(id=self.provider_id, name=self.provider_name, version="1")

    def _resolution(self) -> ToolResolution:
        if self.env_var is not None:
            import os

            configured = os.environ.get(self.env_var)
            if configured:
                return resolve_shell_command(configured)
        if self.tool_names:
            return resolve_tool(self.tool_names, None)
        return ToolResolution(
            False,
            None,
            f"set {self.env_var} to the engine command" if self.env_var else "no tool configured",
        )

    def _availability(self) -> tuple[bool, str | None]:
        resolution = self._resolution()
        return resolution.available, resolution.reason

    def _capability(self, operation: str) -> CapabilityDescriptor:
        available, reason = self._availability()
        return CapabilityDescriptor(
            operation=operation,
            provider=self.identity(),
            available=available,
            reason=reason,
            effects=self.effects,
        )

    def _unavailable(self, operation: str) -> AnalysisError:
        _, reason = self._availability()
        return AnalysisCapabilityUnavailableError(
            message=reason or f"{self.provider_id} is unavailable",
            provider_id=self.provider_id,
            operation=operation,
            reason="provider_unavailable",
        )


class ApktoolProvider(_CliEngine):
    provider_id = "apktool"
    provider_name = "REA-Python Apktool resources"
    tool_names = ("apktool",)
    env_var = "REA_APKTOOL_COMMAND"
    effects = CapabilityEffects(launches_process=True, may_write_filesystem=True)

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (self._capability("decode_android_resources"),)

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format == "apk":
            return TargetSupport("supported")
        return TargetSupport("unsupported", reason="not an APK", code="target_format_unsupported")

    def analyze(self, operation, target, parameters, profile):  # type: ignore[no-untyped-def]
        if operation != "decode_android_resources":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        available, _ = self._availability()
        if not available:
            return err(self._unavailable(operation))
        command = self._resolution().path
        assert command is not None
        output_dir = tempfile.mkdtemp(prefix="rea_mcp-apktool-")
        try:
            argv = [*shlex.split(command), "d", "-f", "-o", output_dir, target.path]
            result = run_owned_process(argv, timeout=300, operation=operation)
            if not result.ok:
                return err(result.error)
            decoded = sorted(
                path.relative_to(output_dir).as_posix()
                for path in Path(output_dir).rglob("*")
                if path.is_file()
            )
            return ok(
                AnalysisExecution(
                    result={
                        "decoded_files": decoded[:1000],
                        "file_count": len(decoded),
                        "truncated": len(decoded) > 1000,
                        "stderr_tail": result.value.stderr[-2000:],
                    },
                    provider=self.identity(),
                    limitations=("Decoded output follows the caller's apktool version.",),
                )
            )
        finally:
            shutil.rmtree(output_dir, ignore_errors=True)


class AdbProvider(_CliEngine):
    provider_id = "adb"
    provider_name = "REA-Python ADB devices"
    tool_names = ("adb",)
    env_var = "REA_ADB_PATH"

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (self._capability("list_adb_devices"), self._capability("list_adb_packages"))

    def supports(self, target: BinaryTarget) -> TargetSupport:
        return TargetSupport("supported")

    def analyze(self, operation, target, parameters, profile):  # type: ignore[no-untyped-def]
        del target, parameters, profile
        available, _ = self._availability()
        if not available:
            return err(self._unavailable(operation))
        adb = self._resolution().path
        assert adb is not None
        if operation == "list_adb_devices":
            argv = [adb, "devices", "-l"]
        elif operation == "list_adb_packages":
            argv = [adb, "shell", "pm", "list", "packages"]
        else:
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        result = run_owned_process(argv, timeout=60, operation=operation)
        if not result.ok:
            return err(result.error)
        lines = [line.strip() for line in result.value.stdout.splitlines() if line.strip()]
        return ok(
            AnalysisExecution(
                result={"lines": lines, "line_count": len(lines)},
                provider=self.identity(),
                limitations=("Requires an attached device or emulator.",),
            )
        )


class SignalProvider(_CliEngine):
    provider_id = "sigrok"
    provider_name = "REA-Python logic signals"
    tool_names = ("sigrok-cli",)
    env_var = "REA_SIGROK"

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (self._capability("decode_signal_recording"),)

    def supports(self, target: BinaryTarget) -> TargetSupport:
        return TargetSupport("supported")

    def analyze(self, operation, target, parameters, profile):  # type: ignore[no-untyped-def]
        del profile
        if operation != "decode_signal_recording":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        available, _ = self._availability()
        if not available:
            return err(self._unavailable(operation))
        tool = self._resolution().path
        assert tool is not None
        decoder = parameters.get("decoder")
        if decoder:
            argv = [tool, "-i", target.path, "-P", str(decoder), "-A", "sigrok"]
        else:
            argv = [tool, "-i", target.path]
        result = run_owned_process(argv, timeout=180, operation=operation)
        if not result.ok:
            return err(result.error)
        return ok(
            AnalysisExecution(
                result={
                    "decoder": decoder,
                    "annotations": result.value.stdout,
                    "stderr_tail": result.value.stderr[-2000:],
                },
                provider=self.identity(),
                limitations=("Decoding uses the caller's sigrok-cli decoder set.",),
            )
        )


class KunaProvider(_CliEngine):
    provider_id = "kuna"
    provider_name = "REA-Python Kuna decompiler"
    tool_names = ()
    env_var = "REA_KUNA_COMMAND"

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (self._capability("kuna_decompile"),)

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format in ("elf", "pe", "mach-o", "mach-o-universal"):
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported", reason="Kuna requires a native binary", code="target_format_unsupported"
        )

    def analyze(self, operation, target, parameters, profile):  # type: ignore[no-untyped-def]
        del profile
        if operation != "kuna_decompile":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        available, _ = self._availability()
        if not available:
            return err(self._unavailable(operation))
        command = self._resolution().path
        assert command is not None
        function = parameters.get("function")
        argv = [*shlex.split(command), target.path]
        if function:
            argv.append(str(function))
        result = run_owned_process(
            argv, timeout=600, operation=operation, max_output_bytes=512 * 1024
        )
        if not result.ok:
            return err(result.error)
        return ok(
            AnalysisExecution(
                result={"function": function, "pseudocode": result.value.stdout},
                provider=self.identity(),
                limitations=("Output follows the caller's Kuna build.",),
            )
        )


# Guard against import removal by keeping the shutil import used in tests.
__all__ = ["AdbProvider", "ApktoolProvider", "KunaProvider", "SignalProvider"]
