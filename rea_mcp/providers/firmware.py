"""Provider for firmware region extraction (built-in signatures, optional Binwalk)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from ..process.supervision import run_owned_process
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .external import resolve_tool
from .formats.firmware_scan import scan_firmware
from .formats.io import open_target
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="firmware", name="REA-Python firmware regions", version="1")
_LINE_RE = re.compile(r"^(?P<offset>\d+)\s+0x[0-9A-Fa-f]+\s+(?P<description>.+)$")


class FirmwareProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        available, _reason = self._availability()
        reason = (
            "Built-in signatures run in-process; binwalk adds extra signatures."
            if available
            else "Built-in signatures run in-process."
        )
        return (
            CapabilityDescriptor(
                operation="inspect_firmware_regions",
                provider=_PROVIDER,
                available=True,
                reason=reason,
                effects=CapabilityEffects(launches_process=available),
                limitations=("The built-in signature set is intentionally small.",),
            ),
            CapabilityDescriptor(
                operation="extract_firmware",
                provider=_PROVIDER,
                available=True,
                reason=reason,
                effects=CapabilityEffects(launches_process=available, may_write_filesystem=True),
                limitations=("Regions are sliced by built-in signature offsets.",),
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
        del profile
        if operation not in ("inspect_firmware_regions", "extract_firmware"):
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        if operation == "extract_firmware":
            return self._extract(target, parameters)
        try:
            with open_target(target.path) as data:
                regions = scan_firmware(data)
        except OSError as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        result: dict[str, Any] = {"regions": regions, "region_count": len(regions)}
        available, _reason = self._availability()
        if available:
            binwalk = resolve_tool(("binwalk",), "REA_BINWALK").path
            if binwalk is not None:
                scanned = run_owned_process(
                    [binwalk, target.path], timeout=180, operation=operation
                )
                if scanned.ok:
                    result["binwalk_regions"] = _parse_regions(scanned.value.stdout)
        return ok(
            AnalysisExecution(
                result=result,
                provider=_PROVIDER,
                limitations=("The built-in signature set is intentionally small.",),
            )
        )

    def _extract(
        self, target: BinaryTarget, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        output_directory = parameters.get("output_directory")
        if not output_directory:
            return err(
                AnalysisInputError(
                    operation="extract_firmware",
                    message="extract_firmware requires output_directory",
                )
            )
        try:
            with open_target(target.path) as data:
                regions = scan_firmware(data)
                out_dir = Path(str(output_directory)).expanduser()
                out_dir.mkdir(parents=True, exist_ok=True)
                extracted: list[dict[str, Any]] = []
                for index, region in enumerate(regions):
                    start = int(region["offset"])
                    end = (
                        int(regions[index + 1]["offset"]) if index + 1 < len(regions) else len(data)
                    )
                    if end <= start:
                        continue
                    destination = out_dir / f"region_{index:03d}_{start:08x}.bin"
                    if destination.exists():
                        continue
                    destination.write_bytes(bytes(data[start:end]))
                    extracted.append(
                        {
                            "path": str(destination),
                            "offset": start,
                            "size": end - start,
                            "description": region["description"],
                        }
                    )
        except OSError as cause:
            return err(AnalysisInputError(operation="extract_firmware", message=str(cause)))
        return ok(
            AnalysisExecution(
                result={
                    "output_directory": str(out_dir),
                    "regions": regions,
                    "extracted": extracted,
                    "extracted_count": len(extracted),
                },
                provider=_PROVIDER,
                limitations=("Regions are sliced by built-in signature offsets.",),
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
