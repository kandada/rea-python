"""PE resource-directory provider (pure Python)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .formats.pe import PeInfo, parse_pe
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="pe-resources", name="REA-Python PE resources", version="1")

_RESOURCE_TYPES = {
    1: "cursor",
    2: "bitmap",
    3: "icon",
    4: "menu",
    5: "dialog",
    6: "string",
    10: "rcdata",
    12: "group-cursor",
    14: "group-icon",
    16: "version",
    24: "manifest",
}


class PeResourcesProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="inspect_pe_resources",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=("Resource types and counts only; resource data is not decoded.",),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format == "pe":
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported", reason="not a PE image", code="target_format_unsupported"
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del parameters, profile
        if operation != "inspect_pe_resources":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        try:
            data = Path(target.path).read_bytes()
        except OSError as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        info = parse_pe(data)
        if info is None:
            return err(AnalysisInputError(operation=operation, message="Not a PE image"))
        if info.resource_rva == 0:
            return ok(
                AnalysisExecution(
                    result={"has_resources": False, "types": []},
                    provider=_PROVIDER,
                    limitations=("No resource directory is present.",),
                )
            )
        base = _rva_to_offset(info, info.resource_rva)
        if base is None:
            return err(
                AnalysisInputError(
                    operation=operation, message="Resource directory is outside the image"
                )
            )
        types = _walk_types(data, base)
        return ok(
            AnalysisExecution(
                result={"has_resources": True, "type_count": len(types), "types": types},
                provider=_PROVIDER,
            )
        )


def _rva_to_offset(pe: PeInfo, rva: int) -> int | None:
    for section in pe.sections:
        span = max(section.virtual_size, section.size_of_raw_data)
        if section.virtual_address <= rva < section.virtual_address + span:
            return rva - section.virtual_address + section.pointer_to_raw_data
    return None


def _walk_types(data: bytes, base: int) -> list[dict[str, Any]]:
    import struct

    if base + 16 > len(data):
        return []
    named, ids = struct.unpack_from("<HH", data, base + 12)
    total = named + ids
    results: list[dict[str, Any]] = []
    for index in range(total):
        entry = base + 16 + index * 8
        if entry + 8 > len(data):
            break
        name_field, offset_field = struct.unpack_from("<II", data, entry)
        if name_field & 0x80000000:
            type_name = _resource_string(data, base + (name_field & 0x7FFFFFFF))
        else:
            type_name = _RESOURCE_TYPES.get(name_field, f"type-{name_field}")
        child_count = 0
        if offset_field & 0x80000000:
            sub = base + (offset_field & 0x7FFFFFFF)
            if sub + 16 <= len(data):
                child_named, child_ids = struct.unpack_from("<HH", data, sub + 12)
                child_count = child_named + child_ids
        results.append({"type": type_name, "name_entries": child_count})
    return results


def _resource_string(data: bytes, offset: int) -> str:
    import struct

    if offset + 2 > len(data):
        return ""
    (length,) = struct.unpack_from("<H", data, offset)
    raw = data[offset + 2 : offset + 2 + length * 2]
    return raw.decode("utf-16-le", errors="replace")


__all__ = ["PeResourcesProvider"]
