"""Pure-Python ELF parser (64/32-bit, little/big-endian).

Returns sections, segments, bounded symbol lists, and mitigation inferences. It
never executes the target and reads only the supplied bytes.
"""

from __future__ import annotations

import mmap
import struct
from dataclasses import dataclass, field
from typing import Any

ELF_MACHINES: dict[int, str] = {
    0x03: "x86",
    0x3E: "x86_64",
    0x28: "arm",
    0xB7: "arm64",
    0x08: "mips",
    0x14: "powerpc",
    0x15: "powerpc64",
    0xF3: "riscv",
}

ELF_TYPES: dict[int, str] = {1: "relocatable", 2: "executable", 3: "shared", 4: "core"}

PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552

PF_X = 0x1
PF_W = 0x2
PF_R = 0x4

SHT_SYMTAB = 2
SHT_DYNSYM = 11

DT_BIND_NOW = 24
DT_FLAGS = 30
DF_BIND_NOW = 0x8

MAX_SYMBOLS = 4096


@dataclass
class ElfSection:
    name: str
    type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    info: int
    addralign: int
    entsize: int


@dataclass
class ElfSegment:
    type: int
    flags: int
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int
    align: int


@dataclass
class ElfInfo:
    elf_class: int
    endian: str
    type: int
    machine: int
    entry: int
    sections: list[ElfSection] = field(default_factory=list)
    segments: list[ElfSegment] = field(default_factory=list)
    dynamic_tags: dict[int, int] = field(default_factory=dict)
    symbol_names: list[str] = field(default_factory=list)
    symbol_truncated: bool = False
    limitations: list[str] = field(default_factory=list)

    @property
    def architecture(self) -> str | None:
        return ELF_MACHINES.get(self.machine)

    @property
    def type_name(self) -> str:
        return ELF_TYPES.get(self.type, "unknown")


def _flags_to_str(flags: int) -> str:
    return "".join(c for c, bit in (("R", PF_R), ("W", PF_W), ("X", PF_X)) if flags & bit)


def parse_elf(data: bytes | mmap.mmap) -> ElfInfo | None:
    if len(data) < 20 or data[:4] != b"\x7fELF":
        return None
    elf_class = data[4]
    endian = "<" if data[5] == 1 else ">"
    if elf_class not in (1, 2):
        return None

    def u16(offset: int) -> int:
        return int(struct.unpack_from(f"{endian}H", data, offset)[0])

    def u32(offset: int) -> int:
        return int(struct.unpack_from(f"{endian}I", data, offset)[0])

    def u64(offset: int) -> int:
        return int(struct.unpack_from(f"{endian}Q", data, offset)[0])

    try:
        e_type = u16(16)
        e_machine = u16(18)
        if elf_class == 2:
            e_entry = u64(24)
            e_phoff = u64(32)
            e_shoff = u64(40)
            e_phentsize = u16(54)
            e_phnum = u16(56)
            e_shentsize = u16(58)
            e_shnum = u16(60)
            e_shstrndx = u16(62)
        else:
            e_entry = u32(24)
            e_phoff = u32(28)
            e_shoff = u32(32)
            e_phentsize = u16(42)
            e_phnum = u16(44)
            e_shentsize = u16(46)
            e_shnum = u16(48)
            e_shstrndx = u16(50)
    except struct.error:
        return None

    info = ElfInfo(
        elf_class=elf_class, endian=endian, type=e_type, machine=e_machine, entry=e_entry
    )

    # Program headers.
    for index in range(e_phnum):
        base = e_phoff + index * e_phentsize
        try:
            if elf_class == 2:
                p_type = u32(base)
                p_flags = u32(base + 4)
                p_offset = u64(base + 8)
                p_vaddr = u64(base + 16)
                p_paddr = u64(base + 24)
                p_filesz = u64(base + 32)
                p_memsz = u64(base + 40)
                p_align = u64(base + 48)
            else:
                p_type = u32(base)
                p_offset = u32(base + 4)
                p_vaddr = u32(base + 8)
                p_paddr = u32(base + 12)
                p_filesz = u32(base + 16)
                p_memsz = u32(base + 20)
                p_flags = u32(base + 24)
                p_align = u32(base + 28)
        except struct.error:
            info.limitations.append("Program header table is truncated")
            break
        info.segments.append(
            ElfSegment(p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align)
        )

    # Section headers.
    sections: list[ElfSection] = []
    name_offsets: list[int] = []
    for _index in range(e_shnum):
        base = e_shoff + _index * e_shentsize
        try:
            name_offset = u32(base)
            if elf_class == 2:
                section = ElfSection(
                    name="",
                    type=u32(base + 4),
                    flags=u64(base + 8),
                    addr=u64(base + 16),
                    offset=u64(base + 24),
                    size=u64(base + 32),
                    link=u32(base + 40),
                    info=u32(base + 44),
                    addralign=u64(base + 48),
                    entsize=u64(base + 56),
                )
            else:
                section = ElfSection(
                    name="",
                    type=u32(base + 4),
                    flags=u32(base + 8),
                    addr=u32(base + 12),
                    offset=u32(base + 16),
                    size=u32(base + 20),
                    link=u32(base + 24),
                    info=u32(base + 28),
                    addralign=u32(base + 32),
                    entsize=u32(base + 36),
                )
        except struct.error:
            info.limitations.append("Section header table is truncated")
            break
        sections.append(section)
        name_offsets.append(name_offset)

    # Resolve section names using the section header string table.
    if sections and e_shstrndx < len(sections):
        strtab = sections[e_shstrndx]
        if strtab.offset + strtab.size <= len(data):
            table = data[strtab.offset : strtab.offset + strtab.size]
            for section, name_offset in zip(sections, name_offsets, strict=True):
                section.name = _cstring(table, name_offset)

    info.sections = sections

    # Dynamic tags for BIND_NOW detection.
    dynamic = next((segment for segment in info.segments if segment.type == PT_DYNAMIC), None)
    if dynamic is not None and dynamic.offset + dynamic.filesz <= len(data):
        entry_size = 16 if elf_class == 2 else 8
        count = dynamic.filesz // entry_size
        for index in range(count):
            base = dynamic.offset + index * entry_size
            try:
                if elf_class == 2:
                    tag = u64(base)
                    value = u64(base + 8)
                else:
                    tag = u32(base)
                    value = u32(base + 4)
            except struct.error:
                break
            info.dynamic_tags[tag] = value
            if tag == 0:
                break

    _collect_symbols(info, data, sections, elf_class, endian)
    return info


def _collect_symbols(
    info: ElfInfo, data: bytes | mmap.mmap, sections: list[ElfSection], elf_class: int, endian: str
) -> None:
    for section in sections:
        if section.type not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        if section.link >= len(sections):
            continue
        strtab_section = sections[section.link]
        if strtab_section.offset + strtab_section.size > len(data):
            continue
        strtab = data[strtab_section.offset : strtab_section.offset + strtab_section.size]
        entry_size = section.entsize or (24 if elf_class == 2 else 16)
        count = section.size // entry_size if entry_size else 0
        for index in range(count):
            base = section.offset + index * entry_size
            if base + entry_size > len(data):
                break
            try:
                st_name = struct.unpack_from(f"{endian}I", data, base)[0]
            except struct.error:
                break
            if st_name == 0:
                continue
            if len(info.symbol_names) >= MAX_SYMBOLS:
                info.symbol_truncated = True
                break
            name = _cstring(strtab, st_name)
            if name:
                info.symbol_names.append(name)


def _cstring(table: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(table):
        return ""
    end = table.find(b"\x00", offset)
    if end == -1:
        end = len(table)
    try:
        return table[offset:end].decode("utf-8", errors="replace")
    except Exception:  # pragma: no cover - decode cannot raise here
        return ""


def elf_mitigations(info: ElfInfo) -> dict[str, Any]:
    """Infer common exploit mitigations. ``None`` means undetermined."""

    segments = info.segments
    has_gnu_stack = any(segment.type == PT_GNU_STACK for segment in segments)
    nx: bool | None
    if has_gnu_stack:
        stack = next(segment for segment in segments if segment.type == PT_GNU_STACK)
        nx = not bool(stack.flags & PF_X)
    else:
        nx = None

    if info.type == 3:
        pie: bool | None = True
    elif info.type == 2:
        pie = False
    else:
        pie = None

    has_relro = any(segment.type == PT_GNU_RELRO for segment in segments)
    bind_now = info.dynamic_tags.get(DT_BIND_NOW) is not None or bool(
        info.dynamic_tags.get(DT_FLAGS, 0) & DF_BIND_NOW
    )
    if not has_relro:
        relro = "none"
    elif bind_now:
        relro = "full"
    else:
        relro = "partial"

    symbols = set(info.symbol_names)
    canary = "__stack_chk_fail" in symbols or "__stack_chk_guard" in symbols
    fortify = any(name.endswith("_chk") for name in symbols)

    return {
        "nx": nx,
        "pie": pie,
        "relro": relro,
        "stack_canary": canary,
        "fortify_source": fortify,
    }


__all__ = ["ELF_MACHINES", "ElfInfo", "ElfSection", "ElfSegment", "elf_mitigations", "parse_elf"]
