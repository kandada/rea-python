"""Provider for digital signal captures (VCD) with a UART decoder."""

from __future__ import annotations

from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .formats.io import open_target
from .formats.vcd import decode_uart, parse_vcd
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="signals", name="REA-Python signal captures", version="1")
_SUPPORTED = {"vcd", "file", "unknown", "raw-binary", "text"}


class SignalCaptureProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="inspect_signal_capture",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=(
                    "Only VCD captures are parsed; binary sigrok formats are not decoded.",
                ),
            ),
            CapabilityDescriptor(
                operation="decode_uart_capture",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=("8N1 UART only; baud must be supplied or defaults to 9600.",),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format in _SUPPORTED:
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported", reason="not a text signal capture", code="target_format_unsupported"
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del profile
        if operation not in ("inspect_signal_capture", "decode_uart_capture"):
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        try:
            with open_target(target.path) as data:
                text = bytes(data).decode("utf-8", "replace")
        except OSError as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        if "$timescale" not in text and "$var" not in text:
            return err(AnalysisInputError(operation=operation, message="Not a VCD capture"))
        parsed = parse_vcd(text)
        signals = parsed["signals"]
        if operation == "inspect_signal_capture":
            return ok(
                AnalysisExecution(
                    result={
                        "timescale_seconds": parsed["timescale_seconds"],
                        "signal_count": len(signals),
                        "signals": {
                            name: len(changes) for name, changes in sorted(signals.items())
                        },
                    },
                    provider=_PROVIDER,
                )
            )
        channel = parameters.get("channel")
        if not channel:
            channel = next((name for name in signals if signals[name]), None)
        if channel is None or channel not in signals:
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unknown signal channel: {channel!r}"
                )
            )
        baud = int(parameters.get("baud") or 9600)
        decoded = decode_uart(
            signals[channel], timescale_seconds=parsed["timescale_seconds"], baud=baud
        )
        decoded["channel"] = channel
        return ok(AnalysisExecution(result=decoded, provider=_PROVIDER))


__all__ = ["SignalCaptureProvider"]
