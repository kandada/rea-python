"""Hopper bridge client.

The bridge (``bridge/hopper_bridge.py``) runs *inside* Hopper and serves a JSON
line protocol over a Unix socket. This provider is the external client: it never
runs Hopper itself, and reports an actionable error when no bridge is configured.
"""

from __future__ import annotations

import json
import os
import socket
from typing import Any

from ..domain.analysis_error import (
    AnalysisCapabilityUnavailableError,
    AnalysisError,
    AnalysisInputError,
    ProviderAdapterError,
)
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="hopper", name="REA-Python Hopper bridge", version="1")
_OPERATIONS = ("hopper_analyze", "hopper_function", "hopper_decompile", "hopper_xrefs")
_ENV = "REA_HOPPER_BRIDGE"
_DEFAULT_TIMEOUT = 60.0


class HopperProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def _socket_path(self) -> str | None:
        return os.environ.get(_ENV)

    def _availability(self) -> tuple[bool, str | None]:
        path = self._socket_path()
        if not path:
            return False, f"set {_ENV} to the running Hopper bridge socket"
        if not os.path.exists(path):
            return False, f"bridge socket {path} was not found"
        return True, None

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        available, reason = self._availability()
        effects = CapabilityEffects(launches_process=False, may_show_ui=True)
        return tuple(
            CapabilityDescriptor(
                operation=operation,
                provider=_PROVIDER,
                available=available,
                reason=reason,
                effects=effects,
                limitations=("Requires a running Hopper with the REA-Python bridge attached.",),
            )
            for operation in _OPERATIONS
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format in ("elf", "pe", "mach-o", "mach-o-universal"):
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported",
            reason="Hopper requires a native binary",
            code="target_format_unsupported",
        )

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
        available, reason = self._availability()
        if not available:
            return err(
                AnalysisCapabilityUnavailableError(
                    message=reason or "Hopper bridge is unavailable",
                    provider_id=_PROVIDER.id,
                    operation=operation,
                    reason="provider_unavailable",
                    remediation_action=(
                        "Start Hopper, run bridge/hopper_bridge.py inside it, and set "
                        f"{_ENV} to the printed socket path."
                    ),
                )
            )
        request = {"operation": operation, "parameters": parameters, "target": target.path}
        response = self._request(request)
        if not response.ok:
            return err(response.error)
        return ok(
            AnalysisExecution(
                result=response.value,
                provider=_PROVIDER,
                limitations=("Analysis is produced by the caller's Hopper session.",),
            )
        )

    def _request(self, request: dict[str, Any]) -> Result[dict[str, Any], AnalysisError]:
        path = self._socket_path()
        assert path is not None
        payload = json.dumps({"id": 1, **request}).encode("utf-8") + b"\n"
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(_DEFAULT_TIMEOUT)
                client.connect(path)
                client.sendall(payload)
                buffer = b""
                while b"\n" not in buffer:
                    chunk = client.recv(65536)
                    if not chunk:
                        break
                    buffer += chunk
        except OSError as cause:
            return err(
                ProviderAdapterError(message=f"Hopper bridge request failed: {cause}"),
            )
        line = buffer.split(b"\n", 1)[0]
        try:
            decoded = json.loads(line.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as cause:
            return err(
                ProviderAdapterError(message=f"Hopper bridge returned malformed data: {cause}")
            )
        if not isinstance(decoded, dict):
            return err(ProviderAdapterError(message="Hopper bridge returned a non-object response"))
        if decoded.get("ok") is not True:
            error = decoded.get("error") or {}
            return err(
                ProviderAdapterError(
                    message=str(error.get("message", "Hopper bridge reported an error")),
                    details={"bridge_error": error},
                )
            )
        result = decoded.get("result")
        return ok(result if isinstance(result, dict) else {"value": result})


__all__ = ["HopperProvider"]
