"""Pure-Python Mach-O parser (single-slice; 32/64-bit, both endiannesses)."""

from __future__ import annotations

import mmap
import struct
import uuid as uuid_module
from dataclasses import dataclass, field

MACHO_CPUS: dict[int, str] = {
    7: "x86",
    0x01000007: "x86_64",
    12: "arm",
    0x0100000C: "arm64",
    18: "powerpc",
    0x01000012: "powerpc64",
}

MACHO_FILETYPES: dict[int, str] = {
    1: "object",
    2: "executable",
    6: "dylib",
    8: "bundle",
    10: "dylinker",
}

_MAGICS: dict[bytes, tuple[str, bool]] = {
    b"\xce\xfa\xed\xfe": ("<", False),
    b"\xcf\xfa\xed\xfe": ("<", True),
    b"\xfe\xed\xfa\xce": (">", False),
    b"\xfe\xed\xfa\xcf": (">", True),
}

LC_SEGMENT = 0x1
LC_SYMTAB = 0x2
LC_SEGMENT_64 = 0x19
LC_UUID = 0x1B
LC_CODE_SIGNATURE = 0x1D
LC_MAIN = 0x80000028
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_DYLD_EXPORTS_TRIE = 0x80000033
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_LOAD_DYLIB = 0xC
LC_ID_DYLIB = 0xD
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB = 0x8000001F
LC_LOAD_UPWARD_DYLIB = 0x80000023
LC_BUILD_VERSION = 0x32

MH_PIE = 0x200000
MH_NO_HEAP_EXECUTION = 0x1000000

_DYLIB_CMDS = {
    LC_LOAD_DYLIB,
    LC_ID_DYLIB,
    LC_LOAD_WEAK_DYLIB,
    LC_REEXPORT_DYLIB,
    LC_LOAD_UPWARD_DYLIB,
}


@dataclass
class MachoSegment:
    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int
    initprot: int


@dataclass
class Machosection:
    name: str
    segment: str
    addr: int
    size: int
    offset: int


@dataclass
class MachoInfo:
    endian: str
    is_64: bool
    cpu_type: int
    filetype: int
    ncmds: int
    flags: int
    entry: int | None = None
    uuid: str | None = None
    has_code_signature: bool = False
    build_tool: str | None = None
    min_os: str | None = None
    segments: list[MachoSegment] = field(default_factory=list)
    sections: list[Machosection] = field(default_factory=list)
    dylibs: list[str] = field(default_factory=list)
    symbols: list[str] = field(default_factory=list)
    symbols_truncated: bool = False
    exports: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    @property
    def architecture(self) -> str | None:
        return MACHO_CPUS.get(self.cpu_type & 0xFFFFFFFF)

    @property
    def filetype_name(self) -> str:
        return MACHO_FILETYPES.get(self.filetype, f"filetype-{self.filetype}")


def parse_macho(data: bytes | mmap.mmap) -> MachoInfo | None:
    if len(data) < 28 or data[:4] not in _MAGICS:
        return None
    endian, is_64 = _MAGICS[data[:4]]

    header_size = 32 if is_64 else 28
    if len(data) < header_size:
        return None
    try:
        cpu_type = struct.unpack_from(f"{endian}I", data, 4)[0]
        filetype = struct.unpack_from(f"{endian}I", data, 12)[0]
        ncmds = struct.unpack_from(f"{endian}I", data, 16)[0]
        flags = struct.unpack_from(f"{endian}I", data, 24)[0]
    except struct.error:
        return None

    info = MachoInfo(
        endian=endian, is_64=is_64, cpu_type=cpu_type, filetype=filetype, ncmds=ncmds, flags=flags
    )

    offset = header_size
    for _ in range(ncmds):
        if offset + 8 > len(data):
            info.limitations.append("Load commands are truncated")
            break
        try:
            cmd, cmdsize = struct.unpack_from(f"{endian}II", data, offset)
        except struct.error:
            break
        if cmdsize < 8 or offset + cmdsize > len(data):
            info.limitations.append("Load command size is invalid")
            break
        _parse_load_command(info, data, offset, cmd, cmdsize, endian, is_64)
        offset += cmdsize
    return info


def _parse_load_command(
    info: MachoInfo,
    data: bytes | mmap.mmap,
    offset: int,
    cmd: int,
    cmdsize: int,
    endian: str,
    is_64: bool,
) -> None:
    base = offset + 8
    if cmd in (LC_SEGMENT, LC_SEGMENT_64):
        try:
            segname_bytes = data[base : base + 16].split(b"\x00", 1)[0]
            segname = segname_bytes.decode("utf-8", errors="replace")
            if is_64:
                vmaddr, vmsize, fileoff, filesize, _maxprot, initprot = struct.unpack_from(
                    f"{endian}QQQQII", data, base + 16
                )
            else:
                vmaddr, vmsize, fileoff, filesize, _maxprot, initprot = struct.unpack_from(
                    f"{endian}IIIIII", data, base + 16
                )
        except struct.error:
            return
        info.segments.append(MachoSegment(segname, vmaddr, vmsize, fileoff, filesize, initprot))
        try:
            nsects = struct.unpack_from(f"{endian}I", data, base + (64 if is_64 else 48))[0]
        except struct.error:
            nsects = 0
        section_base = offset + (72 if is_64 else 56)
        section_size = 80 if is_64 else 68
        for index in range(nsects):
            start = section_base + index * section_size
            try:
                sectname = (
                    data[start : start + 16].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                )
                segment_name = (
                    data[start + 16 : start + 32]
                    .split(b"\x00", 1)[0]
                    .decode("utf-8", errors="replace")
                )
                if is_64:
                    addr, size = struct.unpack_from(f"{endian}QQ", data, start + 32)
                    section_offset = struct.unpack_from(f"{endian}I", data, start + 48)[0]
                else:
                    addr, size = struct.unpack_from(f"{endian}II", data, start + 32)
                    section_offset = struct.unpack_from(f"{endian}I", data, start + 40)[0]
            except struct.error:
                break
            info.sections.append(Machosection(sectname, segment_name, addr, size, section_offset))
    elif cmd == LC_MAIN:
        try:
            (entryoff,) = struct.unpack_from(f"{endian}Q", data, base)
            info.entry = entryoff
        except struct.error:
            return
    elif cmd == LC_UUID:
        raw = data[base : base + 16]
        if len(raw) == 16:
            info.uuid = str(uuid_module.UUID(bytes=raw))
    elif cmd == LC_CODE_SIGNATURE:
        info.has_code_signature = True
    elif cmd == LC_SYMTAB:
        _parse_symtab(info, data, base, endian, is_64)
    elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
        try:
            export_off, export_size = struct.unpack_from(f"{endian}II", data, base + 32)
            info.exports = _parse_export_trie(data, export_off, export_size)
        except struct.error:
            return
    elif cmd == LC_DYLD_EXPORTS_TRIE:
        try:
            dataoff, datasize = struct.unpack_from(f"{endian}II", data, base)
            info.exports = _parse_export_trie(data, dataoff, datasize)
        except struct.error:
            return
    elif cmd == LC_DYLD_CHAINED_FIXUPS:
        try:
            dataoff, datasize = struct.unpack_from(f"{endian}II", data, base)
            info.imports = _parse_chained_fixups(data, dataoff, datasize, endian)
        except struct.error:
            return
    elif cmd == LC_BUILD_VERSION:
        try:
            platform = struct.unpack_from(f"{endian}I", data, base)[0]
            minos = struct.unpack_from(f"{endian}I", data, base + 8)[0]
        except struct.error:
            return
        info.build_tool = _platform_name(platform)
        info.min_os = _version_string(minos)
    elif cmd in _DYLIB_CMDS:
        try:
            (name_offset,) = struct.unpack_from(f"{endian}I", data, base)
        except struct.error:
            return
        name = data[offset + name_offset : offset + cmdsize].split(b"\x00", 1)[0]
        if name:
            info.dylibs.append(name.decode("utf-8", errors="replace"))


_MAX_SYMBOLS = 4096
_MAX_EXPORTS = 4096


def _uleb(data: bytes | mmap.mmap, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            break
        shift += 7
        if shift > 63:
            break
    return result, offset


def _parse_export_trie(data: bytes | mmap.mmap, base: int, size: int) -> list[str]:
    names: list[str] = []
    stack: list[tuple[int, str]] = [(0, "")]
    limit = min(len(data), base + size)
    while stack and len(names) < _MAX_EXPORTS:
        node, prefix = stack.pop()
        cursor = base + node
        if cursor >= limit:
            continue
        terminal_size, cursor = _uleb(data, cursor)
        term_start = cursor
        if terminal_size:
            flags, c = _uleb(data, cursor)
            _addr, c = _uleb(data, c)
            if flags & 0x08:
                _o, c = _uleb(data, c)
            if flags & 0x10:
                _o, c = _uleb(data, c)
            cursor = term_start + terminal_size
            if prefix:
                names.append(prefix)
        if cursor >= limit:
            continue
        child_count = data[cursor]
        cursor += 1
        for _ in range(child_count):
            end = data.find(b"\x00", cursor, limit)
            if end == -1:
                break
            edge = bytes(data[cursor:end]).decode("utf-8", errors="replace")
            cursor = end + 1
            child_off, cursor = _uleb(data, cursor)
            stack.append((child_off, prefix + edge))
    return names


def _parse_chained_fixups(data: bytes | mmap.mmap, base: int, size: int, endian: str) -> list[str]:
    if base + 28 > len(data):
        return []
    (
        _version,
        _starts,
        imports_offset,
        symbols_offset,
        imports_count,
        imports_format,
        _symbols_format,
    ) = struct.unpack_from(f"{endian}IIIIIII", data, base)
    entry_size = {1: 4, 2: 8, 3: 16}.get(imports_format, 4)
    imports_base = base + imports_offset
    symbols_base = base + symbols_offset
    names: list[str] = []
    for index in range(min(imports_count, 8192)):
        entry = imports_base + index * entry_size
        if entry + 4 > len(data):
            break
        raw = struct.unpack_from(f"{endian}I", data, entry)[0]
        name_offset = (raw & 0xFFFFFFFF) if imports_format == 3 else (raw >> 9)
        name = _cstring(data, symbols_base + name_offset)
        if name:
            names.append(name)
    return names


def _parse_symtab(
    info: MachoInfo, data: bytes | mmap.mmap, base: int, endian: str, is_64: bool
) -> None:
    try:
        symoff, nsyms, stroff, strsize = struct.unpack_from(f"{endian}IIII", data, base)
    except struct.error:
        return
    entry_size = 16 if is_64 else 12
    strtab = data[stroff : stroff + strsize]
    for index in range(min(nsyms, _MAX_SYMBOLS)):
        cursor = symoff + index * entry_size
        if cursor + entry_size > len(data):
            break
        try:
            (strx,) = struct.unpack_from(f"{endian}I", data, cursor)
        except struct.error:
            break
        name = _cstring(strtab, strx)
        if name:
            info.symbols.append(name)
    if nsyms > _MAX_SYMBOLS:
        info.symbols_truncated = True


def _cstring(table: bytes | mmap.mmap, offset: int) -> str:
    if offset < 0 or offset >= len(table):
        return ""
    end = table.find(b"\x00", offset)
    if end == -1:
        end = len(table)
    return table[offset:end].decode("utf-8", errors="replace")


def _platform_name(platform: int) -> str:
    return {
        1: "macos",
        2: "ios",
        3: "tvos",
        4: "watchos",
        6: "maccatalyst",
    }.get(platform, f"platform-{platform}")


def _version_string(value: int) -> str:
    major = (value >> 16) & 0xFFFF
    minor = (value >> 8) & 0xFF
    patch = value & 0xFF
    return f"{major}.{minor}.{patch}"


def macho_mitigations(info: MachoInfo) -> dict[str, bool]:
    return {
        "pie": bool(info.flags & MH_PIE),
        "nx_heap": bool(info.flags & MH_NO_HEAP_EXECUTION),
        "code_signature": info.has_code_signature,
    }


_FAT_MAGICS = {b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}


def fat_slices(
    data: bytes | mmap.mmap,
) -> list[tuple[str | None, int, int]] | None:
    """Return ``(architecture, offset, size)`` for each universal slice."""

    if data[:4] not in _FAT_MAGICS:
        return None
    if len(data) < 8:
        return None
    (nfat,) = struct.unpack_from(">I", data, 4)
    if nfat == 0 or nfat > 64:
        return None
    slices: list[tuple[str | None, int, int]] = []
    for index in range(nfat):
        base = 8 + index * 20
        if base + 20 > len(data):
            break
        cpu_type, _cpu_subtype, offset, size, _align = struct.unpack_from(">IIIII", data, base)
        if offset + size > len(data):
            continue
        slices.append((MACHO_CPUS.get(cpu_type & 0xFFFFFFFF), offset, size))
    return slices


def parse_fat_macho(data: bytes | mmap.mmap) -> list[tuple[str | None, bytes]] | None:
    """Return ``(architecture, slice_bytes)`` for a universal (fat) Mach-O."""

    if data[:4] not in _FAT_MAGICS:
        return None
    if len(data) < 8:
        return None
    (nfat,) = struct.unpack_from(">I", data, 4)
    if nfat == 0 or nfat > 64:
        return None
    slices: list[tuple[str | None, bytes]] = []
    for index in range(nfat):
        base = 8 + index * 20
        if base + 20 > len(data):
            break
        cpu_type, _cpu_subtype, offset, size, _align = struct.unpack_from(">IIIII", data, base)
        if offset + size > len(data):
            continue
        arch = MACHO_CPUS.get(cpu_type & 0xFFFFFFFF)
        slices.append((arch, data[offset : offset + size]))
    return slices


__all__ = [
    "MACHO_CPUS",
    "MachoInfo",
    "MachoSegment",
    "fat_slices",
    "macho_mitigations",
    "parse_fat_macho",
    "parse_macho",
]
