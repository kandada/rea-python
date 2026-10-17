"""Provider for firmware region extraction via Binwalk (caller-supplied)."""

from __future__ import annotations

import re
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

_PROVIDER = ProviderIdentity(id="firmware", name="REA-Python firmware regions", version="1")
_LINE_RE = re.compile(r"^(?P<offset>\d+)\s+0x[0-9A-Fa-f]+\s+(?P<description>.+)$")


class FirmwareProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        available, reason = self._availability()
        return (
            CapabilityDescriptor(
                operation="inspect_firmware_regions",
                provider=_PROVIDER,
                available=available,
                reason=reason,
                effects=CapabilityEffects(launches_process=True, may_write_filesystem=True),
                limitations=("Signature coverage follows the caller's binwalk version.",),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format in ("file", "raw-binary", "unknown"):
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported",
            reason="firmware analysis requires a raw image",
            code="target_format_unsupported",
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del profile, parameters
        if operation != "inspect_firmware_regions":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        available, reason = self._availability()
        if not available:
            return err(
                AnalysisCapabilityUnavailableError(
                    message=reason or "binwalk is unavailable",
                    provider_id=_PROVIDER.id,
                    operation=operation,
                    reason="provider_unavailable",
                    remediation_action="Install binwalk or set REA_BINWALK to an absolute path.",
                )
            )
        binwalk = resolve_tool(("binwalk",), "REA_BINWALK").path
        assert binwalk is not None
        result = run_owned_process([binwalk, target.path], timeout=180, operation=operation)
        if not result.ok:
            return err(result.error)
        regions = _parse_regions(result.value.stdout)
        return ok(
            AnalysisExecution(
                result={
                    "regions": regions,
                    "region_count": len(regions),
                    "raw": result.value.stdout,
                    "timed_out": result.value.timed_out,
                },
                provider=_PROVIDER,
                limitations=("Only signatures known to the caller's binwalk are reported.",),
            )
        )

    def _availability(self) -> tuple[bool, str | None]:
        resolution = resolve_tool(("binwalk",), "REA_BINWALK")
        return resolution.available, resolution.reason


def _parse_regions(text: str) -> list[dict[str, Any]]:
    regions: list[dict[str, Any]] = []
    for line in text.splitlines():
        match = _LINE_RE.match(line.strip())
        if match:
            regions.append(
                {
                    "offset": int(match.group("offset")),
                    "description": match.group("description").strip(),
                }
            )
    return regions


__all__ = ["FirmwareProvider"]
