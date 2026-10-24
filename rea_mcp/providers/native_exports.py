"""Pure-Python PE/ELF export table inspection."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .formats.elf import ElfInfo, parse_elf
from .formats.pe import PeInfo, parse_pe
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="native-exports", name="REA-Python native exports", version="1")
_MAX_EXPORTS = 4096


class NativeExportsProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="inspect_native_exports",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=(
                    "Exported names and addresses only; symbol binding and forwarded targets are not resolved.",
                ),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format in ("pe", "elf"):
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported", reason="not a PE or ELF image", code="target_format_unsupported"
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del parameters, profile
        if operation != "inspect_native_exports":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        try:
            data = Path(target.path).read_bytes()
        except OSError as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        try:
            if target.format == "pe":
                pe_info = parse_pe(data)
                if pe_info is None:
                    return err(AnalysisInputError(operation=operation, message="Not a PE image"))
                result = _pe_exports(data, pe_info)
            else:
                elf_info = parse_elf(data)
                if elf_info is None:
                    return err(AnalysisInputError(operation=operation, message="Not an ELF image"))
                result = _elf_exports(data, elf_info)
        except (ValueError, struct.error) as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        return ok(AnalysisExecution(result=result, provider=_PROVIDER))


def _rva(data: bytes, info: PeInfo, rva: int) -> int | None:
    for section in info.sections:
        span = max(section.virtual_size, section.size_of_raw_data)
        if section.virtual_address <= rva < section.virtual_address + span:
            return rva - section.virtual_address + section.pointer_to_raw_data
    return None


def _pe_exports(data: bytes, info: PeInfo) -> dict[str, Any]:
    e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
    optional = e_lfanew + 24
    directory = optional + (112 if info.is_pe32_plus else 96)
    if directory + 8 > len(data):
        raise ValueError("PE optional header is truncated")
    export_rva, export_size = struct.unpack_from("<II", data, directory)
    if export_rva == 0 or export_size == 0:
        return {"format": "pe", "has_exports": False, "exports": [], "export_count": 0}
    offset = _rva(data, info, export_rva)
    if offset is None or offset + 40 > len(data):
        raise ValueError("PE export directory is outside the image")
    (
        _characteristics,
        _timestamp,
        _major,
        _minor,
        name_rva,
        base,
        function_count,
        name_count,
        functions_rva,
        names_rva,
        ordinals_rva,
    ) = struct.unpack_from("<IIHHIIIIIII", data, offset)
    functions_offset = _rva(data, info, functions_rva)
    names_offset = _rva(data, info, names_rva)
    ordinals_offset = _rva(data, info, ordinals_rva)
    if functions_offset is None or names_offset is None or ordinals_offset is None:
        raise ValueError("PE export arrays are outside the image")
    names: dict[int, str] = {}
    for index in range(min(name_count, _MAX_EXPORTS)):
        name_pointer = struct.unpack_from("<I", data, names_offset + index * 4)[0]
        ordinal = struct.unpack_from("<H", data, ordinals_offset + index * 2)[0]
        target = _rva(data, info, name_pointer)
        if target is None:
            raise ValueError("PE export name is outside the image")
        end = data.find(b"\x00", target)
        if end < 0:
            raise ValueError("PE export name is unterminated")
        names[ordinal] = data[target:end].decode("ascii", errors="replace")
    exports = []
    for index in range(min(function_count, _MAX_EXPORTS)):
        function_rva = struct.unpack_from("<I", data, functions_offset + index * 4)[0]
        if function_rva == 0:
            continue
        exports.append(
            {
                "name": names.get(index),
                "ordinal": base + index,
                "rva": function_rva,
                "forwarder": export_rva <= function_rva < export_rva + export_size,
            }
        )
    dll_name = None
    if name_rva:
        target = _rva(data, info, name_rva)
        if target is not None:
            end = data.find(b"\x00", target)
            dll_name = data[target:end].decode("ascii", errors="replace") if end >= 0 else None
    return {
        "format": "pe",
        "has_exports": bool(exports),
        "dll_name": dll_name,
        "export_count": len(exports),
        "exports": exports,
    }


def _elf_exports(data: bytes, info: ElfInfo) -> dict[str, Any]:
    symbols = next((section for section in info.sections if section.name == ".dynsym"), None)
    if symbols is None:
        return {"format": "elf", "has_exports": False, "exports": [], "export_count": 0}
    if symbols.link >= len(info.sections):
        raise ValueError("ELF dynsym has no string table")
    strings = info.sections[symbols.link]
    entry_size = symbols.entsize or (24 if info.elf_class == 2 else 16)
    count = min(symbols.size // entry_size, _MAX_EXPORTS)
    exports: list[dict[str, Any]] = []
    for index in range(count):
        offset = symbols.offset + index * entry_size
        if offset + entry_size > len(data):
            raise ValueError("ELF dynsym extends past the file")
        if info.elf_class == 2:
            name, info_byte, _other, shndx, value, size = struct.unpack_from(
                f"{info.endian}IBBHQQ", data, offset
            )
        else:
            name, value, size, info_byte, _other, shndx = struct.unpack_from(
                f"{info.endian}IIIBBH", data, offset
            )
        bind, kind = info_byte >> 4, info_byte & 0xF
        if shndx == 0 or bind not in (1, 2) or kind not in (1, 2):
            continue
        name_offset = strings.offset + name
        end = data.find(b"\x00", name_offset)
        name_text = data[name_offset:end].decode("utf-8", errors="replace") if end >= 0 else None
        exports.append(
            {
                "name": name_text,
                "value": value,
                "size": size,
                "type": "function" if kind == 2 else "object",
                "binding": "global" if bind == 1 else "weak",
            }
        )
    return {
        "format": "elf",
        "has_exports": bool(exports),
        "export_count": len(exports),
        "exports": exports,
    }


__all__ = ["NativeExportsProvider"]
