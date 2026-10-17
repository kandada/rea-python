"""Built-in static binary-layout provider (ELF / PE / Mach-O)."""

from __future__ import annotations

import mmap
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .formats.elf import elf_mitigations, parse_elf
from .formats.io import open_target
from .formats.macho import macho_mitigations, parse_macho
from .formats.pe import parse_pe, pe_mitigations
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="binary-layout", name="REA-Python binary layout", version="1")
_SUPPORTED_FORMATS = {"elf", "pe", "mach-o", "mach-o-universal", "raw-binary"}


class BinaryLayoutProvider(AnalysisProvider):
    """Parse structural facts and mitigation candidates from native binaries."""

    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="inspect_binary_layout",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=("Static inspection only; the target is never executed.",),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format in _SUPPORTED_FORMATS:
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported",
            reason=f"format {target.format} is not native",
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
        if operation != "inspect_binary_layout":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        try:
            with open_target(target.path) as data:
                if target.format == "elf":
                    result = _layout_elf(data)
                elif target.format == "pe":
                    result = _layout_pe(data)
                elif target.format in ("mach-o", "mach-o-universal"):
                    result = _layout_macho(data)
                else:
                    result = {"format": target.format, "coverage": "unparsed"}
        except OSError as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))

        if result is None:
            return err(
                AnalysisInputError(
                    operation=operation,
                    message=f"Could not parse a {target.format} header for {target.path}",
                )
            )
        return ok(AnalysisExecution(result=result, provider=_PROVIDER))


def _layout_elf(data: bytes | mmap.mmap) -> dict[str, Any] | None:
    info = parse_elf(data)
    if info is None:
        return None
    return {
        "format": "elf",
        "elf_class": info.elf_class,
        "endianness": "little" if info.endian == "<" else "big",
        "type": info.type_name,
        "architecture": info.architecture,
        "entry": hex(info.entry) if info.entry else "0x0",
        "sections": [
            {
                "name": section.name,
                "type": section.type,
                "flags": section.flags,
                "addr": hex(section.addr),
                "offset": section.offset,
                "size": section.size,
            }
            for section in info.sections
        ],
        "segments": [
            {
                "type": segment.type,
                "flags": _segment_flags(segment.flags),
                "offset": segment.offset,
                "vaddr": hex(segment.vaddr),
                "filesz": segment.filesz,
                "memsz": segment.memsz,
            }
            for segment in info.segments
        ],
        "symbols": info.symbol_names[:256],
        "symbols_truncated": info.symbol_truncated,
        "mitigations": elf_mitigations(info),
        "limitations": info.limitations,
    }


def _segment_flags(flags: int) -> str:
    return "".join(c for c, bit in (("R", 0x4), ("W", 0x2), ("X", 0x1)) if flags & bit)


def _layout_pe(data: bytes | mmap.mmap) -> dict[str, Any] | None:
    info = parse_pe(data)
    if info is None:
        return None
    return {
        "format": "pe",
        "pe_kind": "pe32+" if info.is_pe32_plus else "pe32",
        "architecture": info.architecture,
        "subsystem": info.subsystem_name,
        "entry_point": hex(info.entry_point),
        "image_base": hex(info.image_base),
        "has_clr": info.has_clr,
        "sections": [
            {
                "name": section.name,
                "virtual_address": hex(section.virtual_address),
                "virtual_size": section.virtual_size,
                "raw_size": section.size_of_raw_data,
                "characteristics": section.characteristics,
            }
            for section in info.sections
        ],
        "mitigations": pe_mitigations(info),
        "limitations": info.limitations,
    }


def _layout_macho(data: bytes | mmap.mmap) -> dict[str, Any] | None:
    from .formats.macho import parse_fat_macho

    fat = parse_fat_macho(data)
    if fat is not None:
        slices = []
        for arch, slice_bytes in fat:
            info = _macho_slice(slice_bytes)
            if info is None:
                slices.append({"architecture": arch, "error": "slice could not be parsed"})
            else:
                slices.append(info)
        if not slices:
            return None
        return {"format": "mach-o-universal", "slices": slices, "slice_count": len(slices)}

    return _macho_slice(data)


def _macho_slice(data: bytes | mmap.mmap) -> dict[str, Any] | None:
    info = parse_macho(data)
    if info is None:
        return None
    return {
        "format": "mach-o",
        "architecture": info.architecture,
        "filetype": info.filetype_name,
        "is_64": info.is_64,
        "entry_offset": info.entry,
        "uuid": info.uuid,
        "min_os": info.min_os,
        "build_platform": info.build_tool,
        "segments": [
            {
                "name": segment.name,
                "vmaddr": hex(segment.vmaddr),
                "vmsize": segment.vmsize,
                "fileoff": segment.fileoff,
                "filesize": segment.filesize,
            }
            for segment in info.segments
        ],
        "dylibs": info.dylibs,
        "symbols": info.symbols[:512],
        "symbols_truncated": info.symbols_truncated,
        "exports": info.exports[:512],
        "imports": info.imports[:512],
        "mitigations": macho_mitigations(info),
        "limitations": info.limitations,
    }


__all__ = ["BinaryLayoutProvider"]
