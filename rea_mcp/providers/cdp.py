"""Provider for Chrome DevTools Protocol (CDP) runtime observation.

Works against Chrome, Chromium, Electron, and other CDP-speaking runtimes exposed
via ``--remote-debugging-port``. Target discovery is pure HTTP; live network
capture needs the optional ``websocket-client`` package.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
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

_PROVIDER = ProviderIdentity(id="cdp", name="REA-Python CDP runtime", version="1")
_DEFAULT_ENDPOINT = "http://127.0.0.1:9222"


def _endpoint(parameters: dict[str, Any]) -> str:
    endpoint = parameters.get("endpoint") or os.environ.get("REA_CDP_URL") or _DEFAULT_ENDPOINT
    return str(endpoint).rstrip("/")


def _http_json(url: str, timeout: float = 5.0) -> Any:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8", "replace"))


class CdpProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        websocket_available = optional_import("websocket") is not None
        return (
            CapabilityDescriptor(
                operation="inspect_cdp_targets",
                provider=_PROVIDER,
                effects=CapabilityEffects(may_access_network=True),
                limitations=("Requires a runtime started with --remote-debugging-port.",),
            ),
            CapabilityDescriptor(
                operation="capture_cdp_network",
                provider=_PROVIDER,
                available=websocket_available,
                reason=None
                if websocket_available
                else "the optional 'websocket-client' package is not installed",
                effects=CapabilityEffects(may_access_network=True),
                limitations=("Captures request metadata only; response bodies are not stored.",),
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
        if operation == "inspect_cdp_targets":
            return self._inspect_targets(parameters)
        if operation == "capture_cdp_network":
            return self._capture_network(parameters)
        return err(
            AnalysisInputError(operation=operation, message=f"unsupported operation {operation}")
        )

    def _inspect_targets(
        self, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        endpoint = _endpoint(parameters)
        try:
            version = _http_json(f"{endpoint}/json/version")
            targets = _http_json(f"{endpoint}/json/list")
        except (urllib.error.URLError, ValueError, OSError) as cause:
            return err(
                AnalysisCapabilityUnavailableError(
                    message=f"no CDP endpoint at {endpoint}: {cause}",
                    provider_id=_PROVIDER.id,
                    operation="inspect_cdp_targets",
                    reason="provider_unavailable",
                    remediation_action=(
                        "Start Chrome/Chromium/Electron with "
                        "--remote-debugging-port=9222 or set REA_CDP_URL."
                    ),
                )
            )
        if not isinstance(version, dict) or not isinstance(targets, list):
            return err(
                AnalysisInputError(
                    operation="inspect_cdp_targets", message="unexpected CDP response shape"
                )
            )
        return ok(
            AnalysisExecution(
                result={
                    "endpoint": endpoint,
                    "browser": version.get("Browser"),
                    "protocol_version": version.get("Protocol-Version"),
                    "target_count": len(targets),
                    "targets": [
                        {
                            "type": entry.get("type"),
                            "title": entry.get("title"),
                            "url": entry.get("url"),
                            "attachable": bool(entry.get("webSocketDebuggerUrl")),
                        }
                        for entry in targets
                        if isinstance(entry, dict)
                    ],
                },
                provider=_PROVIDER,
                limitations=("Requires a runtime started with --remote-debugging-port.",),
            )
        )

    def _capture_network(
        self, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        websocket = optional_import("websocket")
        if websocket is None:
            return err(
                AnalysisCapabilityUnavailableError(
                    message="the optional 'websocket-client' package is not installed",
                    provider_id=_PROVIDER.id,
                    operation="capture_cdp_network",
                    reason="provider_unavailable",
                    remediation_action="Install websocket-client to stream CDP events.",
                )
            )
        endpoint = _endpoint(parameters)
        duration = float(parameters.get("duration") or 5.0)
        try:
            targets = _http_json(f"{endpoint}/json/list")
        except (urllib.error.URLError, ValueError, OSError) as cause:
            return err(
                AnalysisCapabilityUnavailableError(
                    message=f"no CDP endpoint at {endpoint}: {cause}",
                    provider_id=_PROVIDER.id,
                    operation="capture_cdp_network",
                    reason="provider_unavailable",
                    remediation_action="Start the runtime with --remote-debugging-port.",
                )
            )
        if not isinstance(targets, list):
            return err(
                AnalysisInputError(
                    operation="capture_cdp_network", message="unexpected CDP response"
                )
            )
        requested = parameters.get("target_url")
        page = next(
            (
                entry
                for entry in targets
                if isinstance(entry, dict)
                and entry.get("webSocketDebuggerUrl")
                and (requested is None or entry.get("url") == requested)
                and entry.get("type") in (None, "page")
            ),
            None,
        )
        if page is None:
            return err(
                AnalysisInputError(
                    operation="capture_cdp_network", message="no attachable page target found"
                )
            )
        import time

        connection = websocket.create_connection(page["webSocketDebuggerUrl"], timeout=5)
        try:
            connection.settimeout(1.0)
            connection.send(json.dumps({"id": 1, "method": "Network.enable"}))
            entries: list[dict[str, Any]] = []
            deadline = time.monotonic() + duration
            while time.monotonic() < deadline:
                try:
                    message = json.loads(connection.recv())
                except (TimeoutError, ValueError):
                    continue
                if message.get("method") == "Network.requestWillBeSent":
                    params = message.get("params", {})
                    request = params.get("request", {})
                    entries.append(
                        {
                            "request_id": params.get("requestId"),
                            "method": request.get("method"),
                            "url": request.get("url"),
                            "type": params.get("type"),
                        }
                    )
        finally:
            connection.close()
        return ok(
            AnalysisExecution(
                result={
                    "endpoint": endpoint,
                    "duration": duration,
                    "request_count": len(entries),
                    "requests": entries[:2000],
                },
                provider=_PROVIDER,
                limitations=("Request metadata only; response bodies are not captured.",),
            )
        )


__all__ = ["CdpProvider"]
