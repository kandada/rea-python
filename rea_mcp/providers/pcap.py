"""Provider for saved network captures (built-in parser, optional tshark)."""

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
from .external import ToolResolution, resolve_tool
from .formats.io import open_target
from .formats.pcapfile import parse_capture, parse_packets
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="pcap", name="REA-Python packet captures", version="1")
_OPERATIONS = (
    "inspect_pcap_capture",
    "inspect_packet_capture",
    "inspect_packet_fields",
    "inspect_pcap_client",
)


class PcapProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def _client(self) -> ToolResolution:
        return resolve_tool(("tshark",), "REA_TSHARK")

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        client = self._client()
        available, reason = client.available, client.reason
        return tuple(
            CapabilityDescriptor(
                operation=operation,
                provider=_PROVIDER,
                available=True if operation != "inspect_pcap_client" else available,
                reason=reason if operation == "inspect_pcap_client" else None,
                effects=CapabilityEffects(launches_process=available),
                limitations=("Protocol decoding is limited to IP/TCP/UDP/DNS summaries.",),
            )
            for operation in _OPERATIONS
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format in ("pcap", "file", "unknown"):
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
        del profile
        if operation not in _OPERATIONS:
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        if operation == "inspect_pcap_client":
            return self._inspect_client(operation, target)
        try:
            with open_target(target.path) as data:
                if operation == "inspect_packet_fields":
                    limit = int(parameters.get("limit") or 500)
                    fields = parse_packets(data, limit=limit)
                else:
                    fields = parse_capture(data)
        except OSError as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        if fields is None:
            return err(AnalysisInputError(operation=operation, message="Not a pcap/pcapng capture"))
        result: dict[str, Any] = {"fields": fields}
        available, _reason = self._client().available, self._client().reason
        if available and operation != "inspect_packet_fields":
            tshark = self._client().path
            if tshark is not None:
                hierarchy = run_owned_process(
                    [tshark, "-r", target.path, "-q", "-z", "io,phs"],
                    timeout=120,
                    operation=operation,
                )
                if hierarchy.ok:
                    result["protocol_hierarchy"] = hierarchy.value.stdout
        return ok(
            AnalysisExecution(
                result=result,
                provider=_PROVIDER,
                limitations=("Protocol decoding is limited to IP/TCP/UDP/DNS summaries.",),
            )
        )

    def _inspect_client(
        self, operation: str, target: BinaryTarget
    ) -> Result[AnalysisExecution, AnalysisError]:
        del target
        resolution = self._client()
        if not resolution.available or resolution.path is None:
            return err(
                AnalysisCapabilityUnavailableError(
                    message=resolution.reason or "tshark is unavailable",
                    provider_id=_PROVIDER.id,
                    operation=operation,
                    reason="provider_unavailable",
                    remediation_action="Install Wireshark/tshark or set REA_TSHARK.",
                )
            )
        version = run_owned_process([resolution.path, "--version"], timeout=30, operation=operation)
        banner = version.value.stdout.splitlines()[:3] if version.ok else []
        return ok(
            AnalysisExecution(
                result={"binary": resolution.path, "banner": banner},
                provider=_PROVIDER,
                limitations=("Reports the caller-selected tshark only.",),
            )
        )


__all__ = ["PcapProvider"]
