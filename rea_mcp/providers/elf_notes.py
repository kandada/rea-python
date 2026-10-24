"""Pure-Python ELF PT_NOTE / SHT_NOTE inspection."""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .formats.elf import ElfInfo, parse_elf
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="elf-notes", name="REA-Python ELF notes", version="1")
_PT_NOTE = 4
_SHT_NOTE = 7
_MAX_NOTES = 32


class ElfNotesProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="inspect_elf_notes",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=(
                    "Note descriptors are hashed; only short previews and GNU fields are decoded.",
                ),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format == "elf":
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported", reason="not an ELF image", code="target_format_unsupported"
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del parameters, profile
        if operation != "inspect_elf_notes":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        try:
            data = Path(target.path).read_bytes()
        except OSError as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        info = parse_elf(data)
        if info is None:
            return err(AnalysisInputError(operation=operation, message="Not an ELF image"))
        try:
            result = _notes(data, info)
        except (ValueError, struct.error) as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        return ok(AnalysisExecution(result=result, provider=_PROVIDER))


def _notes(data: bytes, info: ElfInfo) -> dict[str, Any]:
    tables: list[dict[str, Any]] = []
    for segment in info.segments:
        if segment.type == _PT_NOTE:
            tables.append(
                {
                    "kind": "program-header",
                    "name": None,
                    "offset": segment.offset,
                    "size": segment.filesz,
                }
            )
    for section in info.sections:
        if section.type == _SHT_NOTE:
            tables.append(
                {
                    "kind": "section",
                    "name": section.name or None,
                    "offset": section.offset,
                    "size": section.size,
                }
            )
    total_notes = 0
    for table in tables:
        entries, count = _parse_range(data, int(table["offset"]), int(table["size"]), info.endian)
        table["entries"] = entries
        table["entry_count"] = count
        total_notes += count
    return {
        "has_notes": bool(tables),
        "table_count": len(tables),
        "note_count": total_notes,
        "tables": tables,
        "limitations": (["No PT_NOTE or SHT_NOTE table is present."] if not tables else []),
    }


def _parse_range(
    data: bytes, offset: int, size: int, endian: str
) -> tuple[list[dict[str, Any]], int]:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ValueError("ELF note table extends past the file")
    entries: list[dict[str, Any]] = []
    cursor = offset
    end = offset + size
    while cursor + 12 <= end and len(entries) < _MAX_NOTES:
        namesz, descsz, note_type = struct.unpack_from(f"{endian}III", data, cursor)
        cursor += 12
        if namesz > end - cursor:
            raise ValueError("ELF note name extends past its table")
        name_raw = bytes(data[cursor : cursor + namesz])
        cursor += (namesz + 3) & ~3
        if descsz > end - cursor:
            raise ValueError("ELF note descriptor extends past its table")
        desc = bytes(data[cursor : cursor + descsz])
        cursor += (descsz + 3) & ~3
        owner = name_raw.rstrip(b"\x00").decode("utf-8", errors="replace")
        entry: dict[str, Any] = {
            "owner": owner,
            "type": note_type,
            "descriptor_sha256": hashlib.sha256(desc).hexdigest(),
            "descriptor_preview_hex": desc[:64].hex(),
            "gnu": None,
        }
        if owner == "GNU":
            entry["gnu"] = _gnu(note_type, desc)
        entries.append(entry)
    return entries, len(entries)


def _gnu(note_type: int, desc: bytes) -> dict[str, Any] | None:
    if note_type == 3:  # NT_GNU_BUILD_ID
        return {"build_id_hex": desc.hex()}
    if note_type == 1:  # NT_GNU_ABI_TAG
        if len(desc) < 16:
            return {"abi_tag": {"os": None, "major": None, "minor": None, "patch": None}}
        os_id, major, minor, patch = struct.unpack_from("<IIII", desc)
        return {
            "abi_tag": {
                "os": {0: "linux", 1: "gnu", 2: "solaris2", 3: "freebsd"}.get(os_id, os_id),
                "major": major,
                "minor": minor,
                "patch": patch,
            }
        }
    if note_type == 4:  # NT_GNU_GOLD_VERSION
        return {"gold_version": desc.rstrip(b"\x00").decode("utf-8", errors="replace")}
    return None


__all__ = ["ElfNotesProvider"]
