"""Pure-Python PE (Portable Executable) parser."""

from __future__ import annotations

import mmap
import struct
from dataclasses import dataclass, field

PE_MACHINES: dict[int, str] = {
    0x014C: "x86",
    0x8664: "x86_64",
    0x01C0: "arm",
    0xAA64: "arm64",
}

PE_SUBSYSTEMS: dict[int, str] = {
    1: "native",
    2: "windows-gui",
    3: "windows-cui",
    9: "windows-ce",
    10: "efi-application",
}

DIRECTORY_RESOURCE = 2
DIRECTORY_CLR = 14


@dataclass
class PeSection:
    name: str
    virtual_size: int
    virtual_address: int
    size_of_raw_data: int
    pointer_to_raw_data: int
    characteristics: int


@dataclass
class PeInfo:
    machine: int
    number_of_sections: int
    characteristics: int
    magic: int
    is_pe32_plus: bool
    entry_point: int
    image_base: int
    subsystem: int
    dll_characteristics: int
    sections: list[PeSection] = field(default_factory=list)
    clr_header_rva: int = 0
    clr_header_size: int = 0
    resource_rva: int = 0
    resource_size: int = 0
    limitations: list[str] = field(default_factory=list)

    @property
    def architecture(self) -> str | None:
        return PE_MACHINES.get(self.machine)

    @property
    def subsystem_name(self) -> str:
        return PE_SUBSYSTEMS.get(self.subsystem, f"subsystem-{self.subsystem}")

    @property
    def has_clr(self) -> bool:
        return self.clr_header_rva != 0 and self.clr_header_size != 0


def parse_pe(data: bytes | mmap.mmap) -> PeInfo | None:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    try:
        (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    except struct.error:
        return None
    if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return None
    coff = e_lfanew + 4
    try:
        machine, number_of_sections, _timestamp, _symtab, _nsyms, size_opt, characteristics = (
            struct.unpack_from("<HHIIIHH", data, coff)
        )
    except struct.error:
        return None

    opt = coff + 20
    if opt + 2 > len(data):
        return None
    (magic,) = struct.unpack_from("<H", data, opt)
    is_plus = magic == 0x20B
    if magic not in (0x10B, 0x20B):
        return None

    def u32(offset: int) -> int:
        return int(struct.unpack_from("<I", data, offset)[0])

    try:
        entry_point = u32(opt + 16)
        image_base = struct.unpack_from("<Q", data, opt + 24)[0] if is_plus else u32(opt + 28)
        subsystem = struct.unpack_from("<H", data, opt + 68)[0]
        dll_characteristics = struct.unpack_from("<H", data, opt + 70)[0]
    except struct.error:
        return None

    info = PeInfo(
        machine=machine,
        number_of_sections=number_of_sections,
        characteristics=characteristics,
        magic=magic,
        is_pe32_plus=is_plus,
        entry_point=entry_point,
        image_base=image_base,
        subsystem=subsystem,
        dll_characteristics=dll_characteristics,
    )

    # Data directories: count at opt+92 (PE32) / opt+108 (PE32+); array starts +96 / +112.
    dirs_offset = opt + (112 if is_plus else 96)
    try:
        (num_dirs,) = struct.unpack_from("<I", data, opt + (108 if is_plus else 92))
    except struct.error:
        num_dirs = 0
    if num_dirs > DIRECTORY_CLR:
        clr = dirs_offset + DIRECTORY_CLR * 8
        try:
            info.clr_header_rva = u32(clr)
            info.clr_header_size = u32(clr + 4)
        except struct.error:
            info.limitations.append("Data directory table is truncated")
    if num_dirs > DIRECTORY_RESOURCE:
        resource = dirs_offset + DIRECTORY_RESOURCE * 8
        try:
            info.resource_rva = u32(resource)
            info.resource_size = u32(resource + 4)
        except struct.error:
            info.limitations.append("Data directory table is truncated")

    sections_offset = opt + size_opt
    for index in range(number_of_sections):
        base = sections_offset + index * 40
        if base + 40 > len(data):
            info.limitations.append("Section table is truncated")
            break
        raw_name = data[base : base + 8].split(b"\x00", 1)[0]
        name = raw_name.decode("latin-1", errors="replace")
        try:
            (
                virtual_size,
                virtual_address,
                size_raw,
                pointer_raw,
                _prel,
                _plines,
                _nrel,
                _nlines,
                section_flags,
            ) = struct.unpack_from("<IIIIIIHHI", data, base + 8)
        except struct.error:
            info.limitations.append("Section table is truncated")
            break
        info.sections.append(
            PeSection(
                name=name,
                virtual_size=virtual_size,
                virtual_address=virtual_address,
                size_of_raw_data=size_raw,
                pointer_to_raw_data=pointer_raw,
                characteristics=section_flags,
            )
        )
    return info


def pe_mitigations(info: PeInfo) -> dict[str, bool]:
    flags = info.dll_characteristics
    return {
        "nx": bool(flags & 0x0100),
        "aslr": bool(flags & 0x0040),
        "high_entropy_va": bool(flags & 0x0020),
        "control_flow_guard": bool(flags & 0x4000),
        "seh": not bool(flags & 0x0400),
    }


__all__ = ["PE_MACHINES", "PeInfo", "PeSection", "parse_pe", "pe_mitigations"]
