"""Electron fuses provider (pure Python).

Electron embeds a sentinel followed by the fuse wire and one status byte per
fuse (``0`` disabled, ``1`` enabled, ``r`` removed). Reading it reveals security
posture (e.g. asar-integrity validation, Node CLI inspect) before launch.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="electron", name="rea-mcp Electron fuses", version="1")

_SENTINEL = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"
_FUSE_NAMES = (
    "RunAsNode",
    "EnableCookieEncryption",
    "EnableNodeOptionsEnvironmentVariable",
    "EnableNodeCliInspectArguments",
    "EnableEmbeddedAsarIntegrityValidation",
    "OnlyLoadAppFromAsar",
    "LoadBrowserProcessSpecificV8Snapshot",
    "GrantFileProtocolExtraPrivileges",
)


class ElectronFuseProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="inspect_electron_fuses",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=("Static fuse read only; the app is not launched.",),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format in ("pe", "mach-o", "mach-o-universal", "elf", "file", "unknown"):
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported",
            reason="fuse read requires a raw binary",
            code="target_format_unsupported",
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del parameters, profile
        if operation != "inspect_electron_fuses":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        try:
            data = Path(target.path).read_bytes()
        except OSError as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        fuses = _parse_fuses(data)
        if fuses is None:
            return ok(
                AnalysisExecution(
                    result={"is_electron": False, "fuses": {}},
                    provider=_PROVIDER,
                    limitations=("No Electron fuse sentinel was found.",),
                )
            )
        return ok(
            AnalysisExecution(
                result={"is_electron": True, "fuses": fuses},
                provider=_PROVIDER,
            )
        )


def _parse_fuses(data: bytes) -> dict[str, str] | None:
    index = data.find(_SENTINEL)
    if index == -1:
        return None
    cursor = index + len(_SENTINEL)
    if cursor + 1 >= len(data) or data[cursor] != 1:
        return None
    count = data[cursor + 1]
    wire = data[cursor + 2 : cursor + 2 + count]
    fuses: dict[str, str] = {}
    for position, raw in enumerate(wire):
        name = _FUSE_NAMES[position] if position < len(_FUSE_NAMES) else f"fuse_{position}"
        fuses[name] = {0x30: "disabled", 0x31: "enabled", 0x72: "removed"}.get(
            raw, f"unknown:{raw:#x}"
        )
    return fuses


__all__ = ["ElectronFuseProvider"]
