"""CLI-backed engine adapters (caller-supplied): apktool, adb, sigrok, Kuna.

Each adapter reports an actionable capability error when its tool is missing and
runs a bounded, owned subprocess only when the caller supplies the tool.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..domain.analysis_error import (
    AnalysisCapabilityUnavailableError,
    AnalysisError,
    AnalysisInputError,
)
from ..domain.analysis_profile import ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from ..process.supervision import ProcessResult, run_owned_process
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .external import ToolResolution, resolve_shell_command, resolve_tool
from .paging import page_lines, page_sequence
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


_JADX_DEFAULT_TIMEOUT_MS = 120_000
_STRING_TABLE_LIMIT = 2000
_LOCALE_QUALIFIER_RE = re.compile(r"^[a-z]{2,3}(?:-(?:r[A-Z]{2}|[0-9]{3}|[A-Za-z0-9+]+))?$")
_NON_LOCALE_QUALIFIERS = {
    "land",
    "port",
    "square",
    "wide",
    "tall",
    "sw600dp",
    "sw720dp",
    "w600dp",
    "h720dp",
    "night",
    "notnight",
    "ldrtl",
    "ldltr",
    "small",
    "normal",
    "large",
    "xlarge",
    "car",
    "desk",
    "television",
    "watch",
    "vrheadset",
    "anydpi",
    "nodpi",
    "ldpi",
    "mdpi",
    "hdpi",
    "xhdpi",
    "xxhdpi",
    "xxxhdpi",
    "tvdpi",
}


def _jadx_operation_timeout() -> float:
    raw = os.environ.get("REA_JADX_OPERATION_TIMEOUT_MS")
    if raw:
        try:
            value = int(raw)
            if 1 <= value <= 2_147_483_647:
                return value / 1000.0
        except ValueError:
            pass
    return _JADX_DEFAULT_TIMEOUT_MS / 1000.0


def _locale_directory_suffix(locale: str) -> str:
    normalized = locale.strip()
    match = re.fullmatch(r"([a-z]{2,3})-([A-Z]{2})", normalized)
    if match:
        return f"{match.group(1)}-r{match.group(2)}"
    match = re.fullmatch(r"([a-z]{2,3})-([0-9]{3})", normalized)
    if match:
        return f"b+{match.group(1)}+{match.group(2)}"
    return normalized


def _discover_string_locales(root: Path) -> list[str]:
    res = root / "res"
    if not res.is_dir():
        return []
    locales = []
    for entry in res.iterdir():
        if not entry.is_dir() or not entry.name.startswith("values-"):
            continue
        suffix = entry.name[len("values-") :]
        if not (entry / "strings.xml").is_file():
            continue
        if suffix in _NON_LOCALE_QUALIFIERS:
            continue
        if _LOCALE_QUALIFIER_RE.fullmatch(suffix):
            locales.append(suffix)
    return sorted(set(locales))


def _read_string_table(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {
            "status": "missing",
            "strings": [],
            "total_count": None,
            "unparsed_count": None,
        }
    try:
        raw = path.read_bytes()
    except OSError:
        return {"status": "malformed", "strings": [], "total_count": None, "unparsed_count": None}
    if len(raw) > 4_000_000:
        return {"status": "oversized", "strings": [], "total_count": None, "unparsed_count": None}
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return {"status": "malformed", "strings": [], "total_count": None, "unparsed_count": None}
    entries: list[dict[str, str]] = []
    unparsed = 0
    for child in root:
        name = child.attrib.get("name")
        if not name:
            unparsed += 1
            continue
        value = "".join(child.itertext()).strip()
        entries.append({"name": name, "value": value})
    total = len(entries)
    return {
        "status": "present",
        "strings": entries[:_STRING_TABLE_LIMIT],
        "total_count": total,
        "unparsed_count": unparsed,
        "truncated": total > _STRING_TABLE_LIMIT,
    }


def _android_resource_projection(
    root: Path, files: list[str], parameters: dict[str, Any]
) -> dict[str, Any]:
    include_strings = bool(parameters.get("include_strings", True))
    string_tables_only = bool(parameters.get("string_tables_only", False))
    selected_locale = parameters.get("locale")
    requested = parameters.get("locales") or []
    suffixes = sorted({_locale_directory_suffix(str(item)) for item in requested})
    primary_suffix = _locale_directory_suffix(str(selected_locale)) if selected_locale else None
    primary_path = (
        root / "res" / f"values-{primary_suffix}" / "strings.xml"
        if primary_suffix
        else root / "res" / "values" / "strings.xml"
    )
    primary = _read_string_table(primary_path)
    result: dict[str, Any] = {
        "decoded_files": files[:1000],
        "decoded_file_count": len(files),
        "file_count": len(files),
        "truncated": len(files) > 1000,
        "strings": [] if (not include_strings or string_tables_only) else primary["strings"],
        "locale": primary_suffix,
        "locales": _discover_string_locales(root),
        "coverage": "complete" if primary["status"] in ("present", "missing") else "partial",
    }
    if requested or string_tables_only:
        default = _read_string_table(root / "res" / "values" / "strings.xml")
        tables = [{"locale": None, **default}]
        for suffix in suffixes:
            tables.append(
                {
                    "locale": suffix,
                    **_read_string_table(root / "res" / f"values-{suffix}" / "strings.xml"),
                }
            )
        result["string_tables"] = tables
        if any(table["status"] not in ("present", "missing") for table in tables):
            result["coverage"] = "partial"
    return result


class ApktoolProvider(_CliEngine):
    provider_id = "apktool"
    provider_name = "REA-Python Apktool resources"
    tool_names = ("apktool",)
    env_var = "REA_APKTOOL_COMMAND"
    effects = CapabilityEffects(launches_process=True, may_write_filesystem=True)

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            self._capability("decode_android_resources"),
            self._capability("decode_android_smali"),
            self._capability("inspect_apktool_client"),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format == "apk":
            return TargetSupport("supported")
        return TargetSupport("unsupported", reason="not an APK", code="target_format_unsupported")

    def analyze(self, operation, target, parameters, profile):  # type: ignore[no-untyped-def]
        del profile
        if operation not in (
            "decode_android_resources",
            "decode_android_smali",
            "inspect_apktool_client",
        ):
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
        if operation == "inspect_apktool_client":
            probed = run_owned_process(
                [*shlex.split(command), "--version"], timeout=60, operation=operation
            )
            if not probed.ok:
                return err(probed.error)
            return ok(
                AnalysisExecution(
                    result={
                        "binary": command,
                        "version": probed.value.stdout.strip().splitlines()[-1]
                        if probed.value.stdout.strip()
                        else None,
                    },
                    provider=self.identity(),
                )
            )
        output_dir = tempfile.mkdtemp(prefix="rea_mcp-apktool-")
        try:
            argv = [*shlex.split(command), "d", "-f", "-o", output_dir, target.path]
            result = run_owned_process(argv, timeout=300, operation=operation)
            if not result.ok:
                return err(result.error)
            files = sorted(
                path.relative_to(output_dir).as_posix()
                for path in Path(output_dir).rglob("*")
                if path.is_file()
            )
            if operation == "decode_android_smali":
                smali = [name for name in files if name.endswith(".smali")]
                return ok(
                    AnalysisExecution(
                        result={
                            "smali_files": smali[:2000],
                            "smali_count": len(smali),
                            "manifest_decoded": "AndroidManifest.xml" in files,
                            "resource_files": sum(1 for name in files if name.startswith("res/")),
                            "truncated": len(smali) > 2000,
                            "stderr_tail": result.value.stderr[-2000:],
                        },
                        provider=self.identity(),
                        limitations=("Decoded output follows the caller's apktool version.",),
                    )
                )
            projection = _android_resource_projection(Path(output_dir), files, parameters)
            projection["stderr_tail"] = result.value.stderr[-2000:]
            return ok(
                AnalysisExecution(
                    result=projection,
                    provider=self.identity(),
                    limitations=("Decoded output follows the caller's apktool version.",),
                )
            )
        finally:
            shutil.rmtree(output_dir, ignore_errors=True)


_ADB_OPERATIONS = (
    "inspect_adb_client",
    "list_adb_devices",
    "inspect_adb_device",
    "list_adb_packages",
    "pull_adb_package",
    "read_adb_logcat",
    "inspect_adb_package",
    "pull_adb_file",
    "push_adb_file",
    "capture_adb_screen",
    "list_adb_processes",
    "list_adb_directory",
    "list_adb_features",
    "list_adb_services",
    "inspect_adb_display",
    "inspect_adb_window",
    "read_adb_setting",
    "collect_adb_bugreport",
    "resolve_adb_packages",
    "install_adb_package",
    "uninstall_adb_package",
    "start_adb_app",
    "start_adb_activity",
    "stop_adb_app",
    "android_app_info",
    "adb_shell",
)


def _adb_argv(adb: str, serial: str, args: list[str]) -> list[str]:
    return [adb, *(["-s", serial] if serial else []), *args]


def _valid_serial(serial: str) -> bool:
    return bool(serial) and not any(ch.isspace() or ch in "\"'" for ch in serial)


def _pipe_lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def _parse_getprop(text: str) -> dict[str, str]:
    props: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(r"^\[(?P<key>[^\]]+)\]: \[(?P<value>.*)\]$", line.strip())
        if match:
            props[match.group("key")] = match.group("value")
    return props


def _parse_packages(text: str) -> list[dict[str, str | None]]:
    packages: list[dict[str, str | None]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("package:"):
            continue
        payload = line[len("package:") :]
        if "=" in payload:
            path, name = payload.rsplit("=", 1)
            packages.append({"package": name, "path": path})
        else:
            packages.append({"package": payload, "path": None})
    return packages


class AdbProvider(_CliEngine):
    provider_id = "adb"
    provider_name = "REA-Python ADB devices"
    tool_names = ("adb",)
    env_var = "REA_ADB_PATH"
    effects = CapabilityEffects(launches_process=True, may_write_filesystem=True)

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return tuple(self._capability(operation) for operation in _ADB_OPERATIONS)

    def supports(self, target: BinaryTarget) -> TargetSupport:
        return TargetSupport("supported")

    def analyze(self, operation, target, parameters, profile):  # type: ignore[no-untyped-def]
        del target, profile
        if operation not in _ADB_OPERATIONS:
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        available, _ = self._availability()
        if not available:
            return err(self._unavailable(operation))
        adb = self._resolution().path
        assert adb is not None
        handler: (
            Callable[[str, dict[str, Any]], Result[AnalysisExecution, AnalysisError]] | None
        ) = getattr(self, f"_op_{operation}", None)
        if handler is None:
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        return handler(adb, parameters)

    # -- helpers -----------------------------------------------------------

    def _run(
        self,
        argv: list[str],
        operation: str,
        *,
        timeout: float = 60.0,
        max_output: int = 512 * 1024,
    ) -> Result[ProcessResult, AnalysisError]:
        result = run_owned_process(
            argv, timeout=timeout, operation=operation, max_output_bytes=max_output
        )
        if not result.ok:
            return err(result.error)
        return ok(result.value)

    def _serial(
        self, parameters: dict[str, Any], operation: str
    ) -> tuple[str | None, Result[Any, AnalysisError] | None]:
        serial = str(parameters.get("serial") or "").strip()
        if not _valid_serial(serial):
            return None, err(
                AnalysisInputError(
                    operation=operation, message=f"{operation} requires a device serial"
                )
            )
        return serial, None

    def _require(
        self, parameters: dict[str, Any], key: str, operation: str
    ) -> tuple[Any, Result[Any, AnalysisError] | None]:
        value = parameters.get(key)
        if not value:
            return None, err(
                AnalysisInputError(operation=operation, message=f"{operation} requires {key}")
            )
        return value, None

    # -- operations --------------------------------------------------------

    def _op_inspect_adb_client(
        self, adb: str, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        del parameters
        result = self._run([adb, "version"], "inspect_adb_client")
        if not result.ok:
            return err(result.error)
        lines = _pipe_lines(result.value.stdout)
        version = None
        for line in lines:
            match = re.search(r"version\s+([0-9][0-9A-Za-z.\-]*)", line)
            if match:
                version = match.group(1)
                break
        return ok(
            AnalysisExecution(
                result={"binary": adb, "version": version, "banner": lines[:2]},
                provider=self.identity(),
                limitations=("Never contacts a device or starts the adb server.",),
            )
        )

    def _op_list_adb_devices(
        self, adb: str, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        del parameters
        result = self._run([adb, "devices", "-l"], "list_adb_devices")
        if not result.ok:
            return err(result.error)
        lines = _pipe_lines(result.value.stdout)
        devices = []
        for line in lines[1:]:
            parts = line.split()
            if not parts:
                continue
            serial = parts[0]
            state = parts[1] if len(parts) > 1 else "unknown"
            meta = {}
            for token in parts[2:]:
                if ":" in token:
                    key, value = token.split(":", 1)
                    meta[key] = value
            kind = "emulator" if serial.startswith("emulator-") else "physical"
            devices.append(
                {
                    "serial": serial,
                    "state": state,
                    "kind": kind,
                    "model": meta.get("model"),
                    "product": meta.get("product"),
                    "device": meta.get("device"),
                    "transport_id": meta.get("transport_id"),
                }
            )
        return ok(
            AnalysisExecution(
                result={"devices": devices, "device_count": len(devices), "raw_lines": lines},
                provider=self.identity(),
                limitations=("Requires an attached device or emulator.",),
            )
        )

    def _op_inspect_adb_device(
        self, adb: str, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        serial, failure = self._serial(parameters, "inspect_adb_device")
        if failure is not None:
            return failure
        assert serial is not None
        result = self._run(_adb_argv(adb, serial, ["shell", "getprop"]), "inspect_adb_device")
        if not result.ok:
            return err(result.error)
        props = _parse_getprop(result.value.stdout)
        keys = {
            "release": "ro.build.version.release",
            "sdk": "ro.build.version.sdk",
            "security_patch": "ro.build.version.security_patch",
            "fingerprint": "ro.build.fingerprint",
            "model": "ro.product.model",
            "brand": "ro.product.brand",
            "manufacturer": "ro.product.manufacturer",
            "product": "ro.product.name",
            "device": "ro.product.device",
            "abi": "ro.product.cpu.abi",
            "abilist": "ro.product.cpu.abilist",
            "build_type": "ro.build.type",
            "tags": "ro.build.tags",
            "debuggable": "ro.debuggable",
            "qemu": "ro.kernel.qemu",
        }
        observed = {name: props.get(key) for name, key in keys.items()}
        return ok(
            AnalysisExecution(
                result={"serial": serial, "build": observed},
                provider=self.identity(),
                limitations=("Uses a fixed getprop whitelist; other properties are ignored.",),
            )
        )

    def _op_list_adb_packages(
        self, adb: str, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        serial, failure = self._serial(parameters, "list_adb_packages")
        if failure is not None:
            return failure
        assert serial is not None
        scope = str(parameters.get("scope") or "all")
        flags = {"third_party": ["-3"], "system": ["-s"]}.get(scope, [])
        result = self._run(
            _adb_argv(adb, serial, ["shell", "pm", "list", "packages", "-f", *flags]),
            "list_adb_packages",
        )
        if not result.ok:
            return err(result.error)
        packages = _parse_packages(result.value.stdout)
        return ok(
            AnalysisExecution(
                result={
                    "serial": serial,
                    "scope": scope,
                    "packages": packages,
                    "package_count": len(packages),
                },
                provider=self.identity(),
            )
        )

    def _op_resolve_adb_packages(
        self, adb: str, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        serial, failure = self._serial(parameters, "resolve_adb_packages")
        if failure is not None:
            return failure
        assert serial is not None
        query, failure = self._require(parameters, "query", "resolve_adb_packages")
        if failure is not None:
            return failure
        result = self._run(
            _adb_argv(adb, serial, ["shell", "pm", "list", "packages"]),
            "resolve_adb_packages",
        )
        if not result.ok:
            return err(result.error)
        needle = str(query).lower()
        names = [
            item["package"]
            for item in _parse_packages(result.value.stdout)
            if item["package"] and needle in str(item["package"]).lower()
        ]
        return ok(
            AnalysisExecution(
                result={
                    "serial": serial,
                    "query": query,
                    "matches": sorted(names),
                    "match_count": len(names),
                },
                provider=self.identity(),
            )
        )

    def _op_inspect_adb_package(
        self, adb: str, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        serial, failure = self._serial(parameters, "inspect_adb_package")
        if failure is not None:
            return failure
        assert serial is not None
        package, failure = self._require(parameters, "package", "inspect_adb_package")
        if failure is not None:
            return failure
        result = self._run(
            _adb_argv(adb, serial, ["shell", "dumpsys", "package", str(package)]),
            "inspect_adb_package",
        )
        if not result.ok:
            return err(result.error)
        text = result.value.stdout
        facts = {}
        for key in (
            "versionName",
            "versionCode",
            "firstInstallTime",
            "lastUpdateTime",
            "lastUpdateTime",
            "dataDir",
            "codePath",
            "primaryCpuAbi",
            "userId",
        ):
            match = re.search(rf"\b{key}=([^\s]+)", text)
            if match:
                facts[key] = match.group(1)
        return ok(
            AnalysisExecution(
                result={
                    "serial": serial,
                    "package": package,
                    "facts": facts,
                    "lines": text.splitlines()[:400],
                },
                provider=self.identity(),
                limitations=("Parsed from dumpsys package; fields vary by Android version.",),
            )
        )

    def _op_read_adb_logcat(
        self, adb: str, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        serial, failure = self._serial(parameters, "read_adb_logcat")
        if failure is not None:
            return failure
        assert serial is not None
        count = int(parameters.get("count") or 500)
        buffer = str(parameters.get("buffer") or "main")
        argv = _adb_argv(adb, serial, ["logcat", "-d", "-b", buffer, "-t", str(count)])
        pid = parameters.get("pid")
        if pid:
            argv.extend(["--pid", str(pid)])
        result = self._run(argv, "read_adb_logcat", timeout=120)
        if not result.ok:
            return err(result.error)
        lines = result.value.stdout.splitlines()
        return ok(
            AnalysisExecution(
                result={
                    "serial": serial,
                    "buffer": buffer,
                    "lines": lines,
                    "line_count": len(lines),
                },
                provider=self.identity(),
            )
        )

    def _op_pull_adb_file(
        self, adb: str, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        serial, failure = self._serial(parameters, "pull_adb_file")
        if failure is not None:
            return failure
        assert serial is not None
        device_path, failure = self._require(parameters, "device_path", "pull_adb_file")
        if failure is not None:
            return failure
        output_directory, failure = self._require(parameters, "output_directory", "pull_adb_file")
        if failure is not None:
            return failure
        out_dir = Path(str(output_directory)).expanduser()
        destination = out_dir / Path(str(device_path)).name
        if destination.exists():
            return err(
                AnalysisInputError(
                    operation="pull_adb_file", message=f"destination already exists: {destination}"
                )
            )
        out_dir.mkdir(parents=True, exist_ok=True)
        result = self._run(
            _adb_argv(adb, serial, ["pull", str(device_path), str(out_dir)]),
            "pull_adb_file",
            timeout=300,
        )
        if not result.ok:
            return err(result.error)
        return ok(
            AnalysisExecution(
                result={
                    "serial": serial,
                    "device_path": device_path,
                    "path": str(destination),
                    "output": result.value.stdout,
                },
                provider=self.identity(),
            )
        )

    def _op_push_adb_file(
        self, adb: str, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        serial, failure = self._serial(parameters, "push_adb_file")
        if failure is not None:
            return failure
        assert serial is not None
        local_path, failure = self._require(parameters, "local_path", "push_adb_file")
        if failure is not None:
            return failure
        device_path, failure = self._require(parameters, "device_path", "push_adb_file")
        if failure is not None:
            return failure
        if not Path(str(local_path)).is_file():
            return err(
                AnalysisInputError(
                    operation="push_adb_file", message=f"local file not found: {local_path}"
                )
            )
        if not parameters.get("overwrite"):
            probe = self._run(
                _adb_argv(adb, serial, ["shell", "test", "-e", str(device_path)]),
                "push_adb_file",
            )
            if probe.ok and probe.value.exit_code == 0:
                return err(
                    AnalysisInputError(
                        operation="push_adb_file",
                        message=f"device path exists: {device_path} (pass overwrite)",
                    )
                )
        result = self._run(
            _adb_argv(adb, serial, ["push", str(local_path), str(device_path)]),
            "push_adb_file",
            timeout=300,
        )
        if not result.ok:
            return err(result.error)
        return ok(
            AnalysisExecution(
                result={
                    "serial": serial,
                    "local_path": local_path,
                    "device_path": device_path,
                    "output": result.value.stdout,
                },
                provider=self.identity(),
                limitations=("May overwrite the device file only when overwrite is true.",),
            )
        )

    def _op_pull_adb_package(
        self, adb: str, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        serial, failure = self._serial(parameters, "pull_adb_package")
        if failure is not None:
            return failure
        assert serial is not None
        package, failure = self._require(parameters, "package", "pull_adb_package")
        if failure is not None:
            return failure
        output_directory, failure = self._require(
            parameters, "output_directory", "pull_adb_package"
        )
        if failure is not None:
            return failure
        resolved = self._run(
            _adb_argv(adb, serial, ["shell", "pm", "path", str(package)]),
            "pull_adb_package",
        )
        if not resolved.ok:
            return err(resolved.error)
        remote_paths = [
            line[len("package:") :].strip()
            for line in resolved.value.stdout.splitlines()
            if line.strip().startswith("package:")
        ]
        if not remote_paths:
            return err(
                AnalysisInputError(
                    operation="pull_adb_package", message=f"package not found: {package}"
                )
            )
        out_dir = Path(str(output_directory)).expanduser() / str(package)
        out_dir.mkdir(parents=True, exist_ok=True)
        pulled = []
        for remote in remote_paths:
            destination = out_dir / Path(remote).name
            if destination.exists():
                continue
            result = self._run(
                _adb_argv(adb, serial, ["pull", remote, str(destination)]),
                "pull_adb_package",
                timeout=300,
            )
            if result.ok:
                pulled.append(str(destination))
        return ok(
            AnalysisExecution(
                result={
                    "serial": serial,
                    "package": package,
                    "remote_paths": remote_paths,
                    "pulled": pulled,
                },
                provider=self.identity(),
            )
        )

    def _op_capture_adb_screen(
        self, adb: str, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        serial, failure = self._serial(parameters, "capture_adb_screen")
        if failure is not None:
            return failure
        assert serial is not None
        output_directory, failure = self._require(
            parameters, "output_directory", "capture_adb_screen"
        )
        if failure is not None:
            return failure
        out_dir = Path(str(output_directory)).expanduser()
        destination = out_dir / "screen.png"
        if destination.exists():
            return err(
                AnalysisInputError(
                    operation="capture_adb_screen",
                    message=f"destination already exists: {destination}",
                )
            )
        out_dir.mkdir(parents=True, exist_ok=True)
        argv = _adb_argv(adb, serial, ["exec-out", "screencap", "-p"])
        try:
            with destination.open("wb") as handle:
                completed = subprocess.run(
                    argv, stdout=handle, stderr=subprocess.PIPE, timeout=60, check=False
                )
        except subprocess.TimeoutExpired:
            destination.unlink(missing_ok=True)
            return err(
                AnalysisInputError(operation="capture_adb_screen", message="screencap timed out")
            )
        except OSError as cause:
            return err(AnalysisInputError(operation="capture_adb_screen", message=str(cause)))
        if completed.returncode != 0:
            destination.unlink(missing_ok=True)
            return err(
                AnalysisInputError(
                    operation="capture_adb_screen",
                    message=completed.stderr.decode("utf-8", "replace")[-500:],
                )
            )
        return ok(
            AnalysisExecution(
                result={
                    "serial": serial,
                    "path": str(destination),
                    "bytes": destination.stat().st_size,
                },
                provider=self.identity(),
            )
        )

    def _op_list_adb_processes(
        self, adb: str, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        serial, failure = self._serial(parameters, "list_adb_processes")
        if failure is not None:
            return failure
        assert serial is not None
        result = self._run(_adb_argv(adb, serial, ["shell", "ps", "-A"]), "list_adb_processes")
        if not result.ok:
            return err(result.error)
        lines = result.value.stdout.splitlines()
        return ok(
            AnalysisExecution(
                result={"serial": serial, "lines": lines, "line_count": len(lines)},
                provider=self.identity(),
            )
        )

    def _op_list_adb_directory(
        self, adb: str, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        serial, failure = self._serial(parameters, "list_adb_directory")
        if failure is not None:
            return failure
        assert serial is not None
        device_path, failure = self._require(parameters, "device_path", "list_adb_directory")
        if failure is not None:
            return failure
        result = self._run(
            _adb_argv(adb, serial, ["shell", "ls", "-la", str(device_path)]),
            "list_adb_directory",
        )
        if not result.ok:
            return err(result.error)
        lines = result.value.stdout.splitlines()
        return ok(
            AnalysisExecution(
                result={
                    "serial": serial,
                    "device_path": device_path,
                    "lines": lines,
                    "entry_count": len(lines),
                },
                provider=self.identity(),
            )
        )

    def _op_list_adb_features(
        self, adb: str, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        serial, failure = self._serial(parameters, "list_adb_features")
        if failure is not None:
            return failure
        assert serial is not None
        result = self._run(
            _adb_argv(adb, serial, ["shell", "pm", "list", "features"]),
            "list_adb_features",
        )
        if not result.ok:
            return err(result.error)
        features = [
            line[len("feature:") :].strip()
            for line in result.value.stdout.splitlines()
            if line.strip().startswith("feature:")
        ]
        return ok(
            AnalysisExecution(
                result={"serial": serial, "features": features, "feature_count": len(features)},
                provider=self.identity(),
            )
        )

    def _op_list_adb_services(
        self, adb: str, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        serial, failure = self._serial(parameters, "list_adb_services")
        if failure is not None:
            return failure
        assert serial is not None
        result = self._run(
            _adb_argv(adb, serial, ["shell", "service", "list"]), "list_adb_services"
        )
        if not result.ok:
            return err(result.error)
        lines = _pipe_lines(result.value.stdout)
        return ok(
            AnalysisExecution(
                result={"serial": serial, "services": lines, "service_count": len(lines)},
                provider=self.identity(),
            )
        )

    def _op_inspect_adb_display(
        self, adb: str, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        serial, failure = self._serial(parameters, "inspect_adb_display")
        if failure is not None:
            return failure
        assert serial is not None
        result = self._run(
            _adb_argv(adb, serial, ["shell", "dumpsys", "display"]), "inspect_adb_display"
        )
        if not result.ok:
            return err(result.error)
        return ok(
            AnalysisExecution(
                result={"serial": serial, "lines": result.value.stdout.splitlines()[:2000]},
                provider=self.identity(),
            )
        )

    def _op_inspect_adb_window(
        self, adb: str, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        serial, failure = self._serial(parameters, "inspect_adb_window")
        if failure is not None:
            return failure
        assert serial is not None
        result = self._run(
            _adb_argv(adb, serial, ["shell", "dumpsys", "window"]), "inspect_adb_window"
        )
        if not result.ok:
            return err(result.error)
        return ok(
            AnalysisExecution(
                result={"serial": serial, "lines": result.value.stdout.splitlines()[:2000]},
                provider=self.identity(),
            )
        )

    def _op_read_adb_setting(
        self, adb: str, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        serial, failure = self._serial(parameters, "read_adb_setting")
        if failure is not None:
            return failure
        assert serial is not None
        namespace, failure = self._require(parameters, "namespace", "read_adb_setting")
        if failure is not None:
            return failure
        key, failure = self._require(parameters, "key", "read_adb_setting")
        if failure is not None:
            return failure
        result = self._run(
            _adb_argv(adb, serial, ["shell", "settings", "get", str(namespace), str(key)]),
            "read_adb_setting",
        )
        if not result.ok:
            return err(result.error)
        value = result.value.stdout.strip()
        return ok(
            AnalysisExecution(
                result={
                    "serial": serial,
                    "namespace": namespace,
                    "key": key,
                    "value": value,
                    "null": value == "null",
                },
                provider=self.identity(),
            )
        )

    def _op_collect_adb_bugreport(
        self, adb: str, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        serial, failure = self._serial(parameters, "collect_adb_bugreport")
        if failure is not None:
            return failure
        assert serial is not None
        output_directory, failure = self._require(
            parameters, "output_directory", "collect_adb_bugreport"
        )
        if failure is not None:
            return failure
        out_dir = Path(str(output_directory)).expanduser()
        out_dir.mkdir(parents=True, exist_ok=True)
        before = {path.name for path in out_dir.iterdir()}
        result = self._run(
            _adb_argv(adb, serial, ["bugreport", str(out_dir)]),
            "collect_adb_bugreport",
            timeout=600,
        )
        if not result.ok:
            return err(result.error)
        created = sorted({path.name for path in out_dir.iterdir()} - before)
        return ok(
            AnalysisExecution(
                result={
                    "serial": serial,
                    "output_directory": str(out_dir),
                    "created": created,
                    "output": result.value.stdout[-2000:],
                },
                provider=self.identity(),
                limitations=("Bugreport collection can take several minutes on a device.",),
            )
        )

    def _op_install_adb_package(
        self, adb: str, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        serial, failure = self._serial(parameters, "install_adb_package")
        if failure is not None:
            return failure
        assert serial is not None
        apk_path, failure = self._require(parameters, "apk_path", "install_adb_package")
        if failure is not None:
            return failure
        argv = _adb_argv(
            adb, serial, ["install", *(["-r"] if parameters.get("replace") else []), str(apk_path)]
        )
        result = self._run(argv, "install_adb_package", timeout=600)
        if not result.ok:
            return err(result.error)
        return ok(
            AnalysisExecution(
                result={
                    "serial": serial,
                    "apk_path": apk_path,
                    "output": result.value.stdout,
                    "exit_code": result.value.exit_code,
                },
                provider=self.identity(),
            )
        )

    def _op_uninstall_adb_package(
        self, adb: str, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        serial, failure = self._serial(parameters, "uninstall_adb_package")
        if failure is not None:
            return failure
        assert serial is not None
        package, failure = self._require(parameters, "package", "uninstall_adb_package")
        if failure is not None:
            return failure
        result = self._run(
            _adb_argv(adb, serial, ["uninstall", str(package)]),
            "uninstall_adb_package",
            timeout=300,
        )
        if not result.ok:
            return err(result.error)
        return ok(
            AnalysisExecution(
                result={
                    "serial": serial,
                    "package": package,
                    "output": result.value.stdout,
                    "success": "Success" in result.value.stdout,
                },
                provider=self.identity(),
            )
        )

    def _op_start_adb_app(
        self, adb: str, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        serial, failure = self._serial(parameters, "start_adb_app")
        if failure is not None:
            return failure
        assert serial is not None
        package, failure = self._require(parameters, "package", "start_adb_app")
        if failure is not None:
            return failure
        result = self._run(
            _adb_argv(
                adb,
                serial,
                [
                    "shell",
                    "monkey",
                    "-p",
                    str(package),
                    "-c",
                    "android.intent.category.LAUNCHER",
                    "1",
                ],
            ),
            "start_adb_app",
            timeout=120,
        )
        if not result.ok:
            return err(result.error)
        return ok(
            AnalysisExecution(
                result={"serial": serial, "package": package, "output": result.value.stdout},
                provider=self.identity(),
            )
        )

    def _op_start_adb_activity(
        self, adb: str, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        serial, failure = self._serial(parameters, "start_adb_activity")
        if failure is not None:
            return failure
        assert serial is not None
        action, failure = self._require(parameters, "action", "start_adb_activity")
        if failure is not None:
            return failure
        argv = _adb_argv(adb, serial, ["shell", "am", "start", "-a", str(action)])
        if parameters.get("data_uri"):
            argv.extend(["-d", str(parameters["data_uri"])])
        if parameters.get("component"):
            argv.extend(["-n", str(parameters["component"])])
        extra_flags = {
            "string": "--es",
            "boolean": "--ez",
            "int": "--ei",
            "long": "--el",
            "float": "--ef",
        }
        for extra in parameters.get("extras") or []:
            flag = extra_flags.get(str(extra.get("type")))
            if flag:
                argv.extend([flag, str(extra.get("key")), str(extra.get("value"))])
        result = self._run(argv, "start_adb_activity", timeout=120)
        if not result.ok:
            return err(result.error)
        return ok(
            AnalysisExecution(
                result={"serial": serial, "action": action, "output": result.value.stdout},
                provider=self.identity(),
            )
        )

    def _op_stop_adb_app(
        self, adb: str, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        serial, failure = self._serial(parameters, "stop_adb_app")
        if failure is not None:
            return failure
        assert serial is not None
        package, failure = self._require(parameters, "package", "stop_adb_app")
        if failure is not None:
            return failure
        result = self._run(
            _adb_argv(adb, serial, ["shell", "am", "force-stop", str(package)]),
            "stop_adb_app",
            timeout=120,
        )
        if not result.ok:
            return err(result.error)
        return ok(
            AnalysisExecution(
                result={"serial": serial, "package": package, "output": result.value.stdout},
                provider=self.identity(),
            )
        )

    # -- compatibility extras ---------------------------------------------

    def _op_android_app_info(
        self, adb: str, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        return self._op_inspect_adb_package(adb, parameters)

    def _op_adb_shell(
        self, adb: str, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        serial = str(parameters.get("serial") or "").strip()
        command = parameters.get("command")
        if not command:
            return err(
                AnalysisInputError(operation="adb_shell", message="adb_shell requires a command")
            )
        argv = _adb_argv(
            adb,
            serial,
            ["shell", *(command if isinstance(command, list) else shlex.split(str(command)))],
        )
        result = self._run(argv, "adb_shell", timeout=float(parameters.get("timeout") or 60))
        if not result.ok:
            return err(result.error)
        lines = [line.strip() for line in result.value.stdout.splitlines() if line.strip()]
        return ok(
            AnalysisExecution(
                result={
                    "command": argv[1:],
                    "lines": lines,
                    "line_count": len(lines),
                    "truncated": result.value.stdout_truncated,
                },
                provider=self.identity(),
            )
        )


class JadxProvider(_CliEngine):
    provider_id = "jadx"
    provider_name = "REA-Python JADX decompiler"
    tool_names = ("jadx",)
    env_var = "REA_JADX"

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            self._capability("decompile_android_apk"),
            self._capability("decompile_android_class"),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format == "apk":
            return TargetSupport("supported")
        return TargetSupport("unsupported", reason="not an APK", code="target_format_unsupported")

    def analyze(self, operation, target, parameters, profile):  # type: ignore[no-untyped-def]
        del profile
        if operation not in ("decompile_android_apk", "decompile_android_class"):
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
        output_dir = tempfile.mkdtemp(prefix="rea_mcp-jadx-")
        try:
            argv = [*shlex.split(command), "--no-res", "-d", output_dir, target.path]
            result = run_owned_process(
                argv,
                timeout=_jadx_operation_timeout(),
                operation=operation,
                max_output_bytes=512 * 1024,
            )
            if not result.ok:
                return err(result.error)
            java_files = sorted(
                path.relative_to(output_dir).as_posix() for path in Path(output_dir).rglob("*.java")
            )
            if operation == "decompile_android_class":
                wanted = str(parameters.get("class") or "").strip()
                if not wanted:
                    return err(
                        AnalysisInputError(
                            operation=operation, message="decompile_android_class requires a class"
                        )
                    )
                relative = wanted.replace(".", "/") + ".java"
                candidate = next(
                    (
                        path
                        for path in Path(output_dir).rglob("*.java")
                        if (
                            (relative_path := path.relative_to(output_dir).as_posix()) == relative
                            or relative_path.endswith("/" + relative)
                        )
                    ),
                    None,
                )
                if candidate is None:
                    return err(
                        AnalysisInputError(
                            operation=operation,
                            message=f"class {wanted} not found in decompiled output",
                        )
                    )
                source = candidate.read_text(encoding="utf-8", errors="replace")
                page = page_lines(
                    source,
                    offset=int(parameters.get("offset") or 0),
                    limit=int(parameters.get("limit") or 500),
                )
                return ok(
                    AnalysisExecution(
                        result={
                            "class": wanted,
                            "line_count": page["line_total"],
                            "source_bytes": len(source.encode("utf-8")),
                            "source_offset": page["offset"],
                            "next_offset": page["next_offset"],
                            "source": page["text"],
                        },
                        provider=self.identity(),
                        limitations=("Decompilation follows the caller's JADX version.",),
                    )
                )
            page = page_sequence(
                java_files,
                offset=int(parameters.get("offset") or 0),
                limit=int(parameters.get("limit") or 500),
            )
            return ok(
                AnalysisExecution(
                    result={
                        "java_files": page["items"],
                        "java_files_total": page["total"],
                        "java_files_offset": page["offset"],
                        "next_offset": page["next_offset"],
                        "java_file_count": len(java_files),
                        "class_count": len(java_files),
                        "truncated": page["next_offset"] is not None,
                        "stderr_tail": result.value.stderr[-2000:],
                    },
                    provider=self.identity(),
                    limitations=("Decompilation follows the caller's JADX version.",),
                )
            )
        finally:
            shutil.rmtree(output_dir, ignore_errors=True)


class SignalProvider(_CliEngine):
    provider_id = "sigrok"
    provider_name = "REA-Python logic signals"
    tool_names = ("sigrok-cli",)
    env_var = "REA_SIGROK"

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            self._capability("decode_signal_recording"),
            self._capability("inspect_signal_decoders"),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        return TargetSupport("supported")

    def analyze(self, operation, target, parameters, profile):  # type: ignore[no-untyped-def]
        del profile
        if operation == "inspect_signal_decoders":
            available, _ = self._availability()
            if not available:
                return err(self._unavailable(operation))
            tool = self._resolution().path
            assert tool is not None
            listed = run_owned_process([tool, "-L"], timeout=60, operation=operation)
            if not listed.ok:
                return err(listed.error)
            lines = [line.strip() for line in listed.value.stdout.splitlines() if line.strip()]
            decoders = sorted(
                {line.split(":", 1)[1].strip() for line in lines if line.upper().startswith("ID:")}
            )
            return ok(
                AnalysisExecution(
                    result={
                        "decoders": decoders,
                        "decoder_count": len(decoders),
                        "raw_lines": lines[:2000],
                    },
                    provider=self.identity(),
                    limitations=("Decoder set follows the caller's sigrok-cli build.",),
                )
            )
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


_KUNA_OPERATIONS = (
    "kuna_decompile",
    "list_documents",
    "list_procedures",
    "search_procedures",
    "list_strings",
    "search_strings",
    "procedure_address",
    "address_name",
    "procedure_pseudo_code",
    "procedure_assembly",
    "analyze_function",
    "procedure_callers",
    "procedure_callees",
    "xrefs",
)
_KUNA_UNSUPPORTED: dict[str, str] = {}
_KUNA_CACHE: dict[str, tuple[int, int, Any]] = {}
_KUNA_CACHE_LIMIT = 32


def _kuna_timeout() -> float:
    configured = os.environ.get("REA_KUNA_TIMEOUT_MS")
    if configured:
        with contextlib.suppress(ValueError):
            return max(1.0, min(float(configured) / 1000.0, 3600.0))
    return 600.0


def _kuna_json(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return None


def _kuna_records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("functions", "procedures", "items", "strings", "results", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def _kuna_address(record: dict[str, Any]) -> str | None:
    for key in ("address_hex", "address", "addr", "ea", "start", "entry", "offset"):
        value = record.get(key)
        if isinstance(value, int):
            return hex(value)
        if isinstance(value, str) and value:
            return value
    return None


def _kuna_raw_args(
    target: BinaryTarget, parameters: dict[str, Any], *, include_entry: bool = True
) -> list[str]:
    if target.format != "raw-binary":
        return []
    raw_target = parameters.get("target") or parameters.get("raw_target") or "x86:LE:64:default"
    base = parameters.get("base") or parameters.get("base_address") or "0x0"
    arguments = ["--raw-image", "--target", str(raw_target), "--base", str(base)]
    if include_entry:
        entry = parameters.get("entry")
        address = parameters.get("address")
        if entry is not None:
            arguments.extend(["--entry", str(entry)])
        elif address is not None:
            arguments.extend(["--addr", str(address)])
    return arguments


def _kuna_name(record: dict[str, Any]) -> str | None:
    for key in ("name", "procedure", "symbol", "function"):
        value = record.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _same_address(left: str, right: str) -> bool:
    def normalize(value: str) -> Any:
        try:
            return int(value, 0)
        except (TypeError, ValueError):
            return value

    return bool(normalize(left) == normalize(right))


def _kuna_function_slice(text: str, function: str) -> str | None:
    label = re.compile(rf"(?m)^{re.escape(function)}:\s*;")
    match = label.search(text)
    if match is None:
        return None
    start = text.rfind("\n", 0, match.start()) + 1
    following = re.compile(r"(?m)^[^\s;][^:\n]*:\s*;")
    next_match = following.search(text, match.end())
    end = next_match.start() if next_match is not None else len(text)
    return text[start:end].strip("\n") + "\n"


class KunaProvider(_CliEngine):
    provider_id = "kuna"
    provider_name = "REA-Python Kuna static analysis"
    tool_names = ()
    env_var = "REA_KUNA_COMMAND"

    def _resolution(self) -> ToolResolution:
        resolution = super()._resolution()
        if resolution.available:
            return resolution
        for root in (
            Path(os.environ.get("REA_KUNA_HOME", "")),
            Path.cwd(),
            Path(__file__).resolve().parents[3],
        ):
            if not str(root) or not root.is_dir():
                continue
            matches = sorted(
                root.glob("vendor/tools/kuna-*/kuna-*/kuna"),
                reverse=True,
            )
            if matches:
                return resolve_shell_command(str(matches[0]))
        return resolution

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        descriptors = []
        for operation in _KUNA_OPERATIONS:
            if operation in _KUNA_UNSUPPORTED:
                descriptors.append(
                    CapabilityDescriptor(
                        operation=operation,
                        provider=self.identity(),
                        available=False,
                        reason=_KUNA_UNSUPPORTED[operation],
                        effects=self.effects,
                    )
                )
            else:
                descriptors.append(self._capability(operation))
        return tuple(descriptors)

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format in ("elf", "pe", "mach-o", "mach-o-universal", "raw-binary"):
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported", reason="Kuna requires a native binary", code="target_format_unsupported"
        )

    def analyze(self, operation, target, parameters, profile):  # type: ignore[no-untyped-def]
        del profile
        if operation not in _KUNA_OPERATIONS:
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
        if operation == "list_documents":
            return ok(
                AnalysisExecution(result={"documents": [target.path]}, provider=self.identity())
            )
        if operation == "procedure_assembly":
            return self._assembly(
                command,
                target.path,
                parameters,
                operation,
                _kuna_raw_args(target, parameters),
            )
        if operation in (
            "list_procedures",
            "search_procedures",
            "procedure_address",
            "address_name",
        ):
            inventory = self._inventory(
                command, target.path, operation, _kuna_raw_args(target, parameters)
            )
            if not inventory.ok:
                return inventory
            records = _kuna_records(inventory.value)
            if operation == "list_procedures":
                return ok(
                    AnalysisExecution(
                        result={"procedures": inventory.value, "count": len(records)},
                        provider=self.identity(),
                        limitations=("Entries come from Kuna's own discovery.",),
                    )
                )
            if operation == "search_procedures":
                query = str(parameters.get("query") or "").lower()
                matches = [
                    record for record in records if query in (_kuna_name(record) or "").lower()
                ]
                return ok(
                    AnalysisExecution(
                        result={"query": query, "matches": matches[:500], "count": len(matches)},
                        provider=self.identity(),
                    )
                )
            if operation == "procedure_address":
                wanted = str(parameters.get("function") or parameters.get("procedure") or "")
                for record in records:
                    if _kuna_name(record) == wanted:
                        return ok(
                            AnalysisExecution(
                                result={"name": wanted, "address": _kuna_address(record)},
                                provider=self.identity(),
                            )
                        )
                return ok(
                    AnalysisExecution(
                        result={"name": wanted, "address": None}, provider=self.identity()
                    )
                )
            wanted_address = str(parameters.get("address") or "")
            for record in records:
                record_address = _kuna_address(record)
                if record_address and _same_address(record_address, wanted_address):
                    return ok(
                        AnalysisExecution(
                            result={"address": wanted_address, "name": _kuna_name(record)},
                            provider=self.identity(),
                        )
                    )
            return ok(
                AnalysisExecution(
                    result={"address": wanted_address, "name": None}, provider=self.identity()
                )
            )
        if operation in ("list_strings", "search_strings"):
            argv = [
                *shlex.split(command),
                "strings",
                target.path,
                "--json",
                "--encoding",
                "all",
                "--min-length",
                "5",
                "--termination",
                "any",
                "--no-xrefs",
                *_kuna_raw_args(target, parameters),
            ]
            cached = self._cached(command, target.path, "strings", argv, operation)
            if not cached.ok:
                return cached
            parsed = cached.value
            payload = parsed
            if operation == "search_strings":
                query = str(parameters.get("query") or "").lower()
                matches = [
                    record
                    for record in _kuna_records(parsed)
                    if query
                    in str(
                        record.get("value") or record.get("string") or record.get("text") or ""
                    ).lower()
                ]
                return ok(
                    AnalysisExecution(
                        result={"query": query, "matches": matches[:500], "count": len(matches)},
                        provider=self.identity(),
                        limitations=("String scanning skips references.",),
                    )
                )
            return ok(AnalysisExecution(result={"strings": payload}, provider=self.identity()))
        if operation in ("xrefs", "procedure_callers"):
            address = self._resolve_address(
                command, target.path, parameters, operation, _kuna_raw_args(target, parameters)
            )
            if not address.ok:
                return address
            argv = [
                *shlex.split(command),
                "xrefs",
                target.path,
                "--to",
                address.value,
                "--json",
                *_kuna_raw_args(target, parameters),
            ]
            result = self._run(argv, operation)
            if not result.ok:
                return result
            parsed = _kuna_json(result.value.stdout)
            return ok(
                AnalysisExecution(
                    result={
                        "address": address.value,
                        "xrefs": parsed
                        if parsed is not None
                        else {"raw": result.value.stdout[:200_000]},
                    },
                    provider=self.identity(),
                    limitations=("Exact-address incoming references only.",),
                )
            )
        if operation == "procedure_callees":
            argv = [
                *shlex.split(command),
                "decompile-graph",
                target.path,
                "--functions",
                "",
            ]
            result = self._run(argv, operation)
            if not result.ok:
                return result
            parsed = _kuna_json(result.value.stdout)
            return ok(
                AnalysisExecution(
                    result={
                        "callees": parsed
                        if parsed is not None
                        else {"raw": result.value.stdout[:200_000]}
                    },
                    provider=self.identity(),
                    limitations=("Raw decompile-graph output; call-kind edges only.",),
                )
            )
        # pseudocode / analyze_function / kuna_decompile
        address = self._resolve_address(
            command, target.path, parameters, operation, _kuna_raw_args(target, parameters)
        )
        if not address.ok:
            return address
        argv = [
            *shlex.split(command),
            "decompile",
            target.path,
            address.value,
            "--addr",
            *_kuna_raw_args(target, parameters, include_entry=False),
        ]
        result = self._run(argv, operation)
        if not result.ok:
            return result
        pseudocode = result.value.stdout.rstrip("\n")
        data: dict[str, Any] = {
            "function": parameters.get("function") or address.value,
            "address": address.value,
            "pseudocode": pseudocode,
        }
        if operation == "analyze_function":
            data["procedure"] = {
                "name": parameters.get("function"),
                "address": address.value,
            }
        return ok(
            AnalysisExecution(
                result=data,
                provider=self.identity(),
                limitations=("Pseudocode is Kuna text, not original source.",),
            )
        )

    def _run(self, argv: list[str], operation: str) -> Result[Any, AnalysisError]:
        return run_owned_process(
            argv, timeout=_kuna_timeout(), operation=operation, max_output_bytes=512 * 1024
        )

    def _cached(
        self,
        command: str,
        target_path: str,
        cache_operation: str,
        argv: list[str],
        operation: str,
    ) -> Result[Any, AnalysisError]:
        try:
            stat = os.stat(target_path)
        except OSError:
            stat = None
        key = (
            f"{target_path}|{stat.st_mtime_ns}|{stat.st_size}|{cache_operation}"
            if stat is not None
            else f"{target_path}|{cache_operation}"
        )
        cached = _KUNA_CACHE.get(key)
        if cached is not None:
            return ok(cached[2])
        result = self._run(argv, operation)
        if not result.ok:
            return result
        parsed = _kuna_json(result.value.stdout)
        if parsed is None:
            return err(
                AnalysisInputError(
                    operation=operation, message=f"Kuna {cache_operation} is not valid JSON"
                )
            )
        if len(_KUNA_CACHE) >= _KUNA_CACHE_LIMIT:
            _KUNA_CACHE.pop(next(iter(_KUNA_CACHE)))
        if stat is not None:
            _KUNA_CACHE[key] = (stat.st_mtime_ns, stat.st_size, parsed)
        return ok(parsed)

    def _inventory(
        self,
        command: str,
        target_path: str,
        operation: str,
        raw_args: list[str],
    ) -> Result[Any, AnalysisError]:
        return self._cached(
            command,
            target_path,
            "functions",
            [*shlex.split(command), "functions", target_path, "--json", *raw_args],
            operation,
        )

    def _assembly(
        self,
        command: str,
        target_path: str,
        parameters: dict[str, Any],
        operation: str,
        raw_args: list[str],
    ) -> Result[AnalysisExecution, AnalysisError]:
        function = str(parameters.get("function") or parameters.get("procedure") or "")
        output = tempfile.mkdtemp(prefix="rea_mcp-kuna-")
        try:
            result = self._run(
                [
                    *shlex.split(command),
                    "decompile-project",
                    target_path,
                    "-o",
                    output,
                    "--jobs",
                    "1",
                ],
                operation,
            )
            if not result.ok:
                return result
            candidates: list[tuple[Path, str]] = []
            for file in sorted(
                (item for item in Path(output).rglob("*") if item.is_file()),
                key=lambda item: (
                    {".asm": 0, ".s": 1, ".txt": 2, ".json": 3}.get(item.suffix.lower(), 9),
                    item.as_posix(),
                ),
            ):
                if file.suffix.lower() not in (".asm", ".s", ".txt", ".json"):
                    continue
                try:
                    text = file.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if not function or function in text:
                    candidates.append((file, text))
            if not candidates:
                return err(
                    AnalysisInputError(
                        operation=operation,
                        message="Kuna project export did not contain the procedure assembly",
                    )
                )
            file, text = candidates[0]
            sliced = _kuna_function_slice(text, function) if function else None
            return ok(
                AnalysisExecution(
                    result={
                        "function": function or None,
                        "assembly": (sliced or text)[:200_000],
                        "source": file.name,
                        "sliced": sliced is not None,
                    },
                    provider=self.identity(),
                    limitations=(
                        "Assembly is exact Kuna project-export text."
                        if sliced is not None
                        else "Function label was not found in the project export; the full assembly file is returned.",
                    ),
                )
            )
        finally:
            shutil.rmtree(output, ignore_errors=True)

    def _resolve_address(
        self,
        command: str,
        target_path: str,
        parameters: dict[str, Any],
        operation: str,
        raw_args: list[str],
    ) -> Result[str, AnalysisError]:
        candidate = parameters.get("address") or parameters.get("function") or "main"
        value = str(candidate)
        if value.startswith(("0x", "0X")) or value.isdigit():
            return ok(value)
        inventory = self._inventory(command, target_path, operation, raw_args)
        if not inventory.ok:
            return inventory
        for record in _kuna_records(inventory.value):
            if _kuna_name(record) == value:
                address = _kuna_address(record)
                if address:
                    return ok(address)
        return err(
            AnalysisInputError(operation=operation, message=f"Kuna procedure not found: {value}")
        )


# Guard against import removal by keeping the shutil import used in tests.
__all__ = ["AdbProvider", "ApktoolProvider", "JadxProvider", "KunaProvider", "SignalProvider"]
