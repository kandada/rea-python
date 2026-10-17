"""Provider for saved network captures via tshark/capinfos (caller-supplied)."""

from __future__ import annotations

from typing import Any

from ..domain.analysis_error import (
    AnalysisCapabilityUnavailableError,
    AnalysisError,
    AnalysisInputError,
)
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from ..process.supervision import run_owned_process
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .external import resolve_tool
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="pcap", name="REA-Python packet captures", version="1")


class PcapProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        available, reason = self._availability()
        return (
            CapabilityDescriptor(
                operation="inspect_pcap_capture",
                provider=_PROVIDER,
                available=available,
                reason=reason,
                effects=CapabilityEffects(launches_process=True),
                limitations=("Protocol decoding follows the caller's tshark version.",),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format == "pcap":
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported", reason="not a saved capture", code="target_format_unsupported"
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del profile, parameters
        if operation != "inspect_pcap_capture":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        available, reason = self._availability()
        if not available:
            return err(
                AnalysisCapabilityUnavailableError(
                    message=reason or "tshark is unavailable",
                    provider_id=_PROVIDER.id,
                    operation=operation,
                    reason="provider_unavailable",
                    remediation_action="Install Wireshark/tshark or set REA_TSHARK to an absolute path.",
                )
            )
        tshark = resolve_tool(("tshark",), "REA_TSHARK").path
        assert tshark is not None
        hierarchy = run_owned_process(
            [tshark, "-r", target.path, "-q", "-z", "io,phs"], timeout=120, operation=operation
        )
        if not hierarchy.ok:
            return err(hierarchy.error)
        endpoints = run_owned_process(
            [tshark, "-r", target.path, "-q", "-z", "endpoints,ip"],
            timeout=120,
            operation=operation,
        )
        return ok(
            AnalysisExecution(
                result={
                    "protocol_hierarchy": hierarchy.value.stdout,
                    "endpoints": endpoints.value.stdout if endpoints.ok else None,
                },
                provider=_PROVIDER,
                limitations=("Fields follow the caller's tshark dissectors.",),
            )
        )

    def _availability(self) -> tuple[bool, str | None]:
        resolution = resolve_tool(("tshark",), "REA_TSHARK")
        return resolution.available, resolution.reason


__all__ = ["PcapProvider"]
