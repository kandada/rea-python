"""Network capture provider: HAR (JSON) and SAZ (Fiddler zip) files."""

from __future__ import annotations

import json
import shlex
import tempfile
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="network-capture", name="REA-Python network captures", version="1")


class NetworkCaptureProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="inspect_network_capture",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=("Request/response bodies are summarized, not returned verbatim.",),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format in ("har", "saz"):
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported", reason="not a HAR/SAZ capture", code="target_format_unsupported"
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del parameters, profile
        if operation != "inspect_network_capture":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        if target.format == "har":
            return self._har(target)
        if target.format == "saz":
            return self._saz(target)
        return err(AnalysisInputError(operation=operation, message="not a capture"))

    def _har(self, target: BinaryTarget) -> Result[AnalysisExecution, AnalysisError]:
        try:
            payload = json.loads(Path(target.path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as cause:
            return err(AnalysisInputError(operation="inspect_network_capture", message=str(cause)))
        entries = payload.get("log", {}).get("entries", [])
        requests, hosts, methods = _project_har_entries(entries)
        return ok(
            AnalysisExecution(
                result={
                    "capture_format": "har",
                    "entry_count": len(entries),
                    "hosts": dict(hosts),
                    "methods": dict(methods),
                    "requests": requests,
                },
                provider=_PROVIDER,
            )
        )

    def _saz(self, target: BinaryTarget) -> Result[AnalysisExecution, AnalysisError]:
        try:
            with zipfile.ZipFile(target.path) as archive:
                names = archive.namelist()
                sessions = _project_saz(archive, names)
        except (zipfile.BadZipFile, OSError) as cause:
            return err(AnalysisInputError(operation="inspect_network_capture", message=str(cause)))
        return ok(
            AnalysisExecution(
                result={
                    "capture_format": "saz",
                    "session_count": len(sessions),
                    "sessions": sessions,
                },
                provider=_PROVIDER,
            )
        )


def _project_har_entries(
    entries: list[Any],
) -> tuple[list[dict[str, Any]], Counter[str], Counter[str]]:
    from urllib.parse import urlsplit

    requests: list[dict[str, Any]] = []
    hosts: Counter[str] = Counter()
    methods: Counter[str] = Counter()
    for entry in entries[:2000]:
        if not isinstance(entry, dict):
            continue
        request = entry.get("request", {})
        response = entry.get("response", {})
        url = str(request.get("url", ""))
        method = str(request.get("method", ""))
        host = urlsplit(url).hostname or ""
        hosts[host] += 1
        methods[method] += 1
        requests.append(
            {
                "method": method,
                "url": url,
                "host": host,
                "status": response.get("status"),
                "mime_type": (response.get("content") or {}).get("mimeType"),
                "size": (response.get("content") or {}).get("size"),
            }
        )
    return requests, hosts, methods


def _project_saz(archive: zipfile.ZipFile, names: list[str]) -> list[dict[str, Any]]:
    sessions: list[dict[str, Any]] = []
    client_files = sorted(name for name in names if name.endswith("_c.txt"))
    for name in client_files[:2000]:
        session_id = name.rsplit("_c", 1)[0]
        server_name = f"{session_id}_s.txt"
        request_line = _first_line(archive, name)
        status_line = _first_line(archive, server_name) if server_name in names else None
        sessions.append({"session": session_id, "request": request_line, "status": status_line})
    return sessions


def _first_line(archive: zipfile.ZipFile, name: str) -> str | None:
    try:
        with archive.open(name) as handle:
            data = handle.read(4096)
    except (KeyError, OSError):
        return None
    text = data.decode("utf-8", errors="replace")
    return text.splitlines()[0] if text else None


class MitmproxyProvider(AnalysisProvider):
    """Live capture through a caller-supplied mitmproxy (mitmdump)."""

    _IDENTITY = ProviderIdentity(id="mitmproxy", name="REA-Python live capture", version="1")

    def identity(self) -> ProviderIdentity:
        return self._IDENTITY

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        available, reason = self._availability()
        return (
            CapabilityDescriptor(
                operation="capture_live_network",
                provider=self._IDENTITY,
                available=available,
                reason=reason,
                effects=CapabilityEffects(
                    launches_process=True, may_access_network=True, may_write_filesystem=True
                ),
                limitations=("Captures only traffic routed through the launched proxy.",),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        return TargetSupport("supported")

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del target, profile
        from ..domain.analysis_error import AnalysisCapabilityUnavailableError
        from ..process.supervision import run_owned_process

        if operation != "capture_live_network":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        available, reason = self._availability()
        if not available:
            return err(
                AnalysisCapabilityUnavailableError(
                    message=reason or "mitmproxy is unavailable",
                    provider_id=self._IDENTITY.id,
                    operation=operation,
                    reason="provider_unavailable",
                    remediation_action="Install mitmproxy or set REA_MITMPROXY_COMMAND.",
                )
            )
        command = self._command()
        assert command is not None
        duration = float(parameters.get("duration", 5.0))
        port = int(parameters.get("port", 8080))
        har_path = Path(tempfile.mkdtemp(prefix="rea_mcp-mitm-")) / "flows.har"
        argv = [*shlex.split(command), "-q", "-p", str(port), "--set", f"hardump={har_path}"]
        run_owned_process(argv, timeout=duration, operation=operation)
        requests: list[dict[str, Any]] = []
        if har_path.is_file():
            try:
                payload = json.loads(har_path.read_text(encoding="utf-8"))
                requests, _hosts, _methods = _project_har_entries(
                    payload.get("log", {}).get("entries", [])
                )
            except (json.JSONDecodeError, OSError):
                requests = []
        return ok(
            AnalysisExecution(
                result={
                    "duration": duration,
                    "port": port,
                    "request_count": len(requests),
                    "requests": requests,
                },
                provider=self._IDENTITY,
                limitations=("Traffic is captured only for the capture duration.",),
            )
        )

    def _command(self) -> str | None:
        resolution = _resolve_mitmproxy()
        return resolution

    def _availability(self) -> tuple[bool, str | None]:
        command = _resolve_mitmproxy()
        if command is None:
            return False, "mitmdump was not found; set REA_MITMPROXY_COMMAND"
        return True, None


def _resolve_mitmproxy() -> str | None:
    import os

    from .external import resolve_shell_command, resolve_tool

    configured = os.environ.get("REA_MITMPROXY_COMMAND")
    if configured:
        resolution = resolve_shell_command(configured)
        return resolution.path if resolution.available else None
    resolution = resolve_tool(("mitmdump",), None)
    return resolution.path if resolution.available else None


__all__ = ["MitmproxyProvider", "NetworkCaptureProvider"]
