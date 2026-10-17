"""Provider for GDB/pwndbg crash dumps captured as text."""

from __future__ import annotations

import re
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .formats.io import open_target
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="crash", name="REA-Python crash dumps", version="1")
_SIGNAL_RE = re.compile(r"Program received signal (\w+)")
_REGISTER_RE = re.compile(r"^(?P<name>[a-z][a-z0-9]{1,4})\s+(?P<value>0x[0-9a-fA-F]+|\d+)")
_FRAME_RE = re.compile(r"^#(?P<index>\d+)\s+(?:(?P<address>0x[0-9a-fA-F]+)\s+in\s+)?(?P<rest>.+)$")
_SUPPORTED = {"text", "file", "unknown", "raw-binary"}


class CrashDumpProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="inspect_crash_dump",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=("Parses textual GDB/pwndbg output; core files are not read.",),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format in _SUPPORTED:
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported", reason="not a text crash dump", code="target_format_unsupported"
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del profile, parameters
        if operation != "inspect_crash_dump":
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
        parsed = parse_crash_dump(text)
        if parsed is None:
            return err(
                AnalysisInputError(operation=operation, message="Not a recognized crash dump")
            )
        return ok(AnalysisExecution(result=parsed, provider=_PROVIDER))


def parse_crash_dump(text: str) -> dict[str, Any] | None:
    signal = None
    fault_address = None
    stopped_at = None
    registers: dict[str, str] = {}
    backtrace: list[dict[str, Any]] = []
    is_pwndbg = "pwndbg" in text.lower()
    for line in text.splitlines():
        stripped = line.strip()
        signal_match = _SIGNAL_RE.search(stripped)
        if signal_match:
            signal = signal_match.group(1)
            continue
        if stripped.startswith("Program received signal") and " 0x" in stripped:
            address_match = re.search(r"0x[0-9a-fA-F]+", stripped)
            fault_address = address_match.group(0) if address_match else None
            continue
        frame_match = _FRAME_RE.match(stripped)
        if frame_match:
            backtrace.append(
                {
                    "index": int(frame_match.group("index")),
                    "address": frame_match.group("address"),
                    "detail": frame_match.group("rest").strip(),
                }
            )
            continue
        register_match = _REGISTER_RE.match(stripped)
        if register_match and len(register_match.group("name")) <= 4:
            registers[register_match.group("name")] = register_match.group("value")
    if signal is None and not backtrace and not registers:
        return None
    if fault_address is None:
        instruction = re.search(r"rip\s+(0x[0-9a-fA-F]+)", text)
        fault_address = instruction.group(1) if instruction else None
    stopped_at = backtrace[0]["detail"] if backtrace else None
    return {
        "debugger": "pwndbg" if is_pwndbg else "gdb",
        "signal": signal,
        "fault_address": fault_address,
        "stopped_at": stopped_at,
        "register_count": len(registers),
        "registers": registers,
        "backtrace": backtrace,
    }


__all__ = ["CrashDumpProvider", "parse_crash_dump"]
