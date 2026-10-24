"""CLI (Common Language Infrastructure) metadata reader.

Decodes .NET metadata tables enough to recover assembly members: TypeDef and
MethodDef names (with Field/Method counts) from the ``#~`` table stream and the
``#Strings`` heap. Pure Python; the assembly is never loaded or executed.
"""

from __future__ import annotations

import mmap
import struct
import uuid
from dataclasses import dataclass
from typing import Any

STRING_HEAP_4 = 0x01
GUID_HEAP_4 = 0x02
BLOB_HEAP_4 = 0x04

# Table indices used here.
MODULE = 0x00
TYPEREF = 0x01
TYPEDEF = 0x02
FIELDPTR = 0x03
FIELD = 0x04
METHODPTR = 0x05
METHODDEF = 0x06
PARAM = 0x08
MEMBERREF = 0x0A
CONSTANT = 0x0B
CUSTOMATTRIBUTE = 0x0C
MODULEREF = 0x1A
TYPESPEC = 0x1B
IMPLMAP = 0x1C
PROPERTY = 0x17
ASSEMBLY = 0x20
ASSEMBLYREF = 0x23
EXPORTEDTYPE = 0x27
MANIFESTRESOURCE = 0x28
NESTEDCLASS = 0x29

# Column schema: ('u1'|'u2'|'u4'|'str'|'guid'|'blob'| ('idx', table) | ('coded', tables, bits))
_SIMPLE_TABLES: dict[int, list[Any]] = {
    0x00: [("u2", None), ("str", None), ("guid", None), ("guid", None), ("guid", None)],
    0x01: [("coded", (0x00, 0x1A, 0x23, 0x01), 2), ("str", None), ("str", None)],
    0x02: [
        ("u4", None),
        ("str", None),
        ("str", None),
        ("coded", (0x02, 0x01, 0x1B), 2),
        ("idx", 0x04),
        ("idx", 0x06),
    ],
    0x03: [("idx", 0x04)],
    0x04: [("u2", None), ("str", None), ("blob", None)],
    0x05: [("idx", 0x06)],
    0x06: [("u4", None), ("u2", None), ("u2", None), ("str", None), ("blob", None), ("idx", 0x08)],
    0x07: [("idx", 0x08)],
    0x08: [("u2", None), ("u2", None), ("str", None)],
    0x09: [("idx", 0x02), ("coded", (0x02, 0x01, 0x1B), 2)],
    0x0A: [("coded", (0x02, 0x01, 0x1A, 0x06, 0x1B), 3), ("str", None), ("blob", None)],
    0x0B: [("u2", None), ("coded", (0x04, 0x08, 0x17), 2), ("blob", None)],
    0x0C: [
        (
            "coded",
            (
                0x06,
                0x04,
                0x01,
                0x02,
                0x08,
                0x09,
                0x0A,
                0x00,
                0x0E,
                0x17,
                0x14,
                0x11,
                0x1A,
                0x1B,
                0x20,
                0x23,
                0x26,
                0x27,
                0x28,
                0x2A,
                0x2C,
                0x2B,
            ),
            5,
        ),
        ("coded", (0x06, 0x0A), 3),
        ("blob", None),
    ],
    0x0D: [("coded", (0x04, 0x08), 1), ("blob", None)],
    0x0E: [("u2", None), ("coded", (0x02, 0x06, 0x20), 2), ("blob", None)],
    0x0F: [("u2", None), ("u4", None), ("idx", 0x02)],
    0x10: [("u4", None), ("idx", 0x04)],
    0x11: [("blob", None)],
    0x12: [("idx", 0x02), ("idx", 0x14)],
    0x13: [("idx", 0x14)],
    0x14: [("u2", None), ("str", None), ("coded", (0x02, 0x01, 0x1B), 2)],
    0x15: [("idx", 0x02), ("idx", 0x17)],
    0x16: [("idx", 0x17)],
    0x17: [("u2", None), ("str", None), ("blob", None)],
    0x18: [("u2", None), ("idx", 0x06), ("coded", (0x14, 0x17), 1)],
    0x19: [("idx", 0x02), ("coded", (0x06, 0x0A), 1), ("coded", (0x06, 0x0A), 1)],
    0x1A: [("str", None)],
    0x1B: [("blob", None)],
    0x1C: [("u2", None), ("coded", (0x04, 0x06), 1), ("str", None), ("idx", 0x1A)],
    0x1D: [("u4", None), ("idx", 0x04)],
    0x20: [
        ("u4", None),
        ("u2", None),
        ("u2", None),
        ("u2", None),
        ("u2", None),
        ("u4", None),
        ("blob", None),
        ("str", None),
        ("str", None),
    ],
    0x21: [("u4", None)],
    0x22: [("u4", None), ("u4", None), ("u4", None)],
    0x23: [
        ("u2", None),
        ("u2", None),
        ("u2", None),
        ("u2", None),
        ("u4", None),
        ("blob", None),
        ("str", None),
        ("str", None),
        ("blob", None),
    ],
    0x24: [("u4", None), ("idx", 0x23)],
    0x25: [("u4", None), ("u4", None), ("u4", None), ("idx", 0x23)],
    0x26: [("u4", None), ("str", None), ("blob", None)],
    0x27: [
        ("u4", None),
        ("u4", None),
        ("str", None),
        ("str", None),
        ("coded", (0x26, 0x23, 0x27), 2),
    ],
    0x28: [("u4", None), ("u4", None), ("str", None), ("coded", (0x26, 0x23, 0x27), 2)],
    0x29: [("idx", 0x02), ("idx", 0x02)],
    0x2A: [("u2", None), ("u2", None), ("coded", (0x02, 0x06), 1), ("str", None)],
    0x2B: [("coded", (0x06, 0x0A), 1), ("blob", None)],
    0x2C: [("idx", 0x2A), ("coded", (0x02, 0x01, 0x1B), 2)],
}


class MetadataError(ValueError):
    pass


def _simple_index(rows: dict[int, int], table: int) -> int:
    return 4 if rows.get(table, 0) >= 0x10000 else 2


def _coded_index(rows: dict[int, int], tables: tuple[int, ...], bits: int) -> int:
    largest = max((rows.get(table, 0) for table in tables), default=0)
    return 4 if largest >= (1 << (16 - bits)) else 2


def _row_size(table: int, heap: int, rows: dict[int, int]) -> int:
    total = 0
    for column in _SIMPLE_TABLES.get(table, []):
        kind = column[0]
        if kind == "u1":
            total += 1
        elif kind == "u2":
            total += 2
        elif kind == "u4":
            total += 4
        elif kind == "str":
            total += 4 if heap & STRING_HEAP_4 else 2
        elif kind == "guid":
            total += 4 if heap & GUID_HEAP_4 else 2
        elif kind == "blob":
            total += 4 if heap & BLOB_HEAP_4 else 2
        elif kind == "idx":
            total += _simple_index(rows, column[1])
        elif kind == "coded":
            total += _coded_index(rows, column[1], column[2])
    return total


def _read_uleb(data: bytes | mmap.mmap, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            break
        shift += 7
    return result, offset


def _string_at(data: bytes | mmap.mmap, base: int, index: int) -> str:
    if index <= 0:
        return ""
    start = base + index
    end = data.find(b"\x00", start)
    if end == -1:
        return ""
    return bytes(data[start:end]).decode("utf-8", errors="replace")


def _tables_header(
    data: bytes | mmap.mmap,
    streams: dict[str, int],
    stream_sizes: dict[str, int] | None = None,
) -> tuple[int, dict[int, int], int, str] | None:
    """Read the #~ or #- table header and return heap flags, rows and data start."""

    name = "#~" if "#~" in streams else "#-" if "#-" in streams else None
    if name is None:
        return None
    tables_base = streams[name]
    if tables_base + 24 > len(data):
        return None
    heap = data[tables_base + 6]
    valid = int.from_bytes(bytes(data[tables_base + 8 : tables_base + 16]), "little")
    cursor = tables_base + 24
    rows: dict[int, int] = {}
    for index in range(64):
        if valid & (1 << index):
            if cursor + 4 > len(data):
                return None
            rows[index] = int.from_bytes(bytes(data[cursor : cursor + 4]), "little")
            cursor += 4
    expected = 0
    complete = True
    for index in sorted(rows):
        if index not in _SIMPLE_TABLES:
            complete = False
            break
        expected += _row_size(index, heap, rows) * rows[index]
    size = (stream_sizes or {}).get(name)
    if size is not None and complete:
        remaining = tables_base + size - cursor
        # CLR readers accept an optional 4-byte ExtraData word after row counts.
        if remaining == expected + 4:
            cursor += 4
        elif remaining < expected:
            return None
    return heap, rows, cursor, name


def parse_managed_members(
    data: bytes | mmap.mmap,
    streams: dict[str, int],
    stream_sizes: dict[str, int] | None = None,
) -> dict[str, Any] | None:
    """Recover member names from the metadata table stream."""

    header = _tables_header(data, streams, stream_sizes)
    strings_base = streams.get("#Strings")
    if header is None or strings_base is None:
        return None
    heap, rows, rows_start, _tables_name = header

    # Offsets of each present table within the rows block.
    offsets: dict[int, int] = {}
    position = rows_start
    for index in sorted(rows):
        if index not in _SIMPLE_TABLES:
            break
        offsets[index] = position
        position += _row_size(index, heap, rows) * rows[index]
    if TYPEDEF not in offsets:
        return None

    types = _type_rows(data, strings_base, heap, rows, offsets)
    return {
        "type_count": rows.get(TYPEDEF, 0),
        "method_count": rows.get(METHODDEF, 0),
        "field_count": rows.get(FIELD, 0),
        "types": types,
    }


def _type_rows(
    data: bytes | mmap.mmap,
    strings_base: int,
    heap: int,
    rows: dict[int, int],
    offsets: dict[int, int],
) -> list[dict[str, Any]]:
    if TYPEDEF not in offsets:
        return []
    str_size = 4 if heap & STRING_HEAP_4 else 2
    field_index = _simple_index(rows, FIELD)
    method_index = _simple_index(rows, METHODDEF)
    extends_size = _coded_index(rows, (TYPEDEF, TYPEREF, 0x1B), 2)
    row_size = _row_size(TYPEDEF, heap, rows)

    method_names = _method_rows(data, strings_base, heap, rows, offsets)
    types: list[dict[str, Any]] = []
    base = offsets[TYPEDEF]
    for i in range(rows.get(TYPEDEF, 0)):
        start = base + i * row_size
        cursor = start + 4  # Flags
        name = _string_at(data, strings_base, _read_index(data, cursor, str_size))
        cursor += str_size
        namespace = _string_at(data, strings_base, _read_index(data, cursor, str_size))
        cursor += str_size + extends_size
        cursor += field_index  # FieldList
        method_list_start = _read_index(data, cursor, method_index)
        cursor += method_index
        next_method = (
            _read_index(
                data,
                base + (i + 1) * row_size + 4 + str_size * 2 + extends_size + field_index,
                method_index,
            )
            if i + 1 < rows.get(TYPEDEF, 0)
            else rows.get(METHODDEF, 0) + 1
        )
        method_slice = method_names[method_list_start - 1 : max(0, next_method - 1)]
        full_name = f"{namespace}.{name}" if namespace else name
        types.append(
            {"full_name": full_name, "namespace": namespace, "name": name, "methods": method_slice}
        )
    return types


def _method_rows(
    data: bytes | mmap.mmap,
    strings_base: int,
    heap: int,
    rows: dict[int, int],
    offsets: dict[int, int],
) -> list[dict[str, Any]]:
    if METHODDEF not in offsets:
        return []
    str_size = 4 if heap & STRING_HEAP_4 else 2
    row_size = _row_size(METHODDEF, heap, rows)
    base = offsets[METHODDEF]
    result: list[dict[str, Any]] = []
    for i in range(rows.get(METHODDEF, 0)):
        row = base + i * row_size
        rva = struct.unpack_from("<I", data, row)[0]
        name_index = _read_index(data, row + 4 + 2 + 2, str_size)
        result.append({"name": _string_at(data, strings_base, name_index), "rva": rva})
    return result


def _read_index(data: bytes | mmap.mmap, offset: int, size: int) -> int:
    if size == 2:
        return int(struct.unpack_from("<H", data, offset)[0])
    return int(struct.unpack_from("<I", data, offset)[0])


@dataclass
class MetadataContext:
    data: bytes | mmap.mmap
    strings_base: int
    us_base: int | None
    heap: int
    rows: dict[int, int]
    offsets: dict[int, int]
    blob_base: int | None = None
    guid_base: int | None = None
    tables_name: str = "#~"
    stream_sizes: dict[str, int] | None = None

    @property
    def string_size(self) -> int:
        return 4 if self.heap & STRING_HEAP_4 else 2

    @property
    def blob_size(self) -> int:
        return 4 if self.heap & BLOB_HEAP_4 else 2

    @property
    def guid_size(self) -> int:
        return 4 if self.heap & GUID_HEAP_4 else 2

    def row_size(self, table: int) -> int:
        return _row_size(table, self.heap, self.rows)

    def row_offset(self, table: int, row: int) -> int | None:
        if row <= 0 or table not in self.offsets:
            return None
        return self.offsets[table] + (row - 1) * self.row_size(table)

    def row_count(self, table: int) -> int:
        return self.rows.get(table, 0)

    def read_index(self, offset: int, size: int | None = None) -> int:
        return _read_index(self.data, offset, self.string_size if size is None else size)

    def read_string(self, index: int) -> str:
        return _string_at(self.data, self.strings_base, index)

    def read_blob(self, index: int) -> bytes:
        if self.blob_base is None or index <= 0:
            return b""
        start = self.blob_base + index
        if start >= len(self.data):
            return b""
        length, cursor = _read_uleb(self.data, start)
        return bytes(self.data[cursor : cursor + length])

    def read_guid(self, index: int) -> str | None:
        if self.guid_base is None or index <= 0:
            return None
        start = self.guid_base + (index - 1) * 16
        raw = bytes(self.data[start : start + 16])
        if len(raw) != 16:
            return None
        return str(uuid.UUID(bytes_le=raw))

    def simple_size(self, table: int) -> int:
        return _simple_index(self.rows, table)

    def coded_size(self, tables: tuple[int, ...], bits: int) -> int:
        return _coded_index(self.rows, tables, bits)

    def coded_token(self, raw: int, tables: tuple[int, ...], bits: int) -> tuple[int, int] | None:
        tag = raw & ((1 << bits) - 1)
        row = raw >> bits
        if row <= 0 or tag >= len(tables):
            return None
        return tables[tag], row

    @staticmethod
    def token(table: int, row: int) -> str:
        return f"0x{(table << 24) | row:08x}"

    def row_label(self, table: int, row: int) -> str | None:
        offset = self.row_offset(table, row)
        if offset is None:
            return None
        return _row_label(self, table, row, offset)


def load_metadata(
    data: bytes | mmap.mmap,
    streams: dict[str, int],
    stream_sizes: dict[str, int] | None = None,
) -> MetadataContext | None:
    """Load a context suitable for member recovery and token resolution."""

    header = _tables_header(data, streams, stream_sizes)
    strings_base = streams.get("#Strings")
    if header is None or strings_base is None:
        return None
    heap, rows, rows_start, _tables_name = header
    offsets: dict[int, int] = {}
    position = rows_start
    for index in sorted(rows):
        if index not in _SIMPLE_TABLES:
            break
        offsets[index] = position
        position += _row_size(index, heap, rows) * rows[index]
    return MetadataContext(
        data=data,
        strings_base=strings_base,
        us_base=streams.get("#US"),
        heap=heap,
        rows=rows,
        offsets=offsets,
        blob_base=streams.get("#Blob"),
        guid_base=streams.get("#GUID"),
        tables_name=_tables_name,
        stream_sizes=stream_sizes,
    )


def resolve_token(context: MetadataContext, token: int) -> str | None:
    """Resolve a CIL metadata token to a member/type/string name when possible."""

    table = token >> 24
    row = token & 0xFFFFFF
    if table == 0x70:  # UserString
        return _user_string(context, row)
    if row == 0 or table not in context.offsets:
        return None
    row_offset = context.offsets[table] + (row - 1) * _row_size(table, context.heap, context.rows)
    return _row_label(context, table, row, row_offset)


def _user_string(context: MetadataContext, offset: int) -> str | None:
    if context.us_base is None:
        return None
    start = context.us_base + offset
    if start >= len(context.data):
        return None
    length, cursor = _read_uleb(context.data, start)
    raw = bytes(context.data[cursor : cursor + length])
    usable = len(raw) - (len(raw) % 2)
    return raw[:usable].decode("utf-16-le", errors="replace")


def _row_label(context: MetadataContext, table: int, row: int, row_offset: int) -> str | None:
    size = context.string_size
    data, base = context.data, context.strings_base
    if table == TYPEDEF:
        name = _string_at(data, base, _read_index(data, row_offset + 4, size))
        namespace = _string_at(data, base, _read_index(data, row_offset + 4 + size, size))
        return f"{namespace}.{name}" if namespace else name
    if table == TYPEREF:
        scope = _coded_index(context.rows, (MODULE, 0x1A, 0x23, TYPEREF), 2)
        name = _string_at(data, base, _read_index(data, row_offset + scope, size))
        namespace = _string_at(data, base, _read_index(data, row_offset + scope + size, size))
        return f"{namespace}.{name}" if namespace else name
    if table == FIELD:
        return _string_at(data, base, _read_index(data, row_offset + 2, size))
    if table == METHODDEF:
        return _string_at(data, base, _read_index(data, row_offset + 8, size))
    if table == 0x0A:  # MemberRef
        class_index = _coded_index(context.rows, (TYPEDEF, TYPEREF, 0x1A, METHODDEF, 0x1B), 3)
        name = _string_at(data, base, _read_index(data, row_offset + class_index, size))
        return name or None
    if table == 0x1B:  # TypeSpec
        return "<typespec>"
    return f"token:0x{((table << 24) | row):08x}"


__all__ = [
    "MetadataContext",
    "MetadataError",
    "load_metadata",
    "parse_managed_members",
    "resolve_token",
]


_CALL_CONVENTIONS = {
    0x0100: "winapi",
    0x0200: "cdecl",
    0x0300: "stdcall",
    0x0400: "thiscall",
    0x0500: "fastcall",
}


def parse_pinvoke(
    data: bytes | mmap.mmap,
    streams: dict[str, int],
    stream_sizes: dict[str, int] | None = None,
) -> list[dict[str, Any]] | None:
    """Decode ImplMap rows into P/Invoke declarations."""

    context = load_metadata(data, streams, stream_sizes)
    if context is None:
        return None
    if 0x1C not in context.offsets:
        return []
    row_size = _row_size(0x1C, context.heap, context.rows)
    mf_size = _coded_index(context.rows, (0x04, 0x06), 1)
    modref_size = _simple_index(context.rows, 0x1A)
    str_size = 4 if context.heap & STRING_HEAP_4 else 2
    base = context.offsets[0x1C]
    results: list[dict[str, Any]] = []
    for index in range(context.rows.get(0x1C, 0)):
        offset = base + index * row_size
        flags = struct.unpack_from("<H", data, offset)[0]
        cursor = offset + 2
        member = _read_index(data, cursor, mf_size)
        cursor += mf_size
        name_index = _read_index(data, cursor, str_size)
        cursor += str_size
        scope = _read_index(data, cursor, modref_size)
        tag = member & 1
        row = member >> 1
        method = _methoddef_name(context, row) if tag == 1 and row else None
        library = _moduleref_name(context, scope) if scope else None
        results.append(
            {
                "method": method,
                "native_library": library,
                "entry_point": _string_at(data, context.strings_base, name_index),
                "flags": flags,
                "character_set": {0x0002: "ansi", 0x0004: "unicode", 0x0006: "auto"}.get(
                    flags & 0x0006
                ),
                "calling_convention": _CALL_CONVENTIONS.get(flags & 0x0700),
                "supports_last_error": bool(flags & 0x0040),
            }
        )
    return results


def _methoddef_name(context: MetadataContext, row: int) -> str | None:
    if 0x06 not in context.offsets or row <= 0:
        return None
    str_size = 4 if context.heap & STRING_HEAP_4 else 2
    row_size = _row_size(0x06, context.heap, context.rows)
    offset = context.offsets[0x06] + (row - 1) * row_size
    name_index = _read_index(context.data, offset + 8, str_size)
    return _string_at(context.data, context.strings_base, name_index)


def _moduleref_name(context: MetadataContext, row: int) -> str | None:
    if 0x1A not in context.offsets or row <= 0:
        return None
    str_size = 4 if context.heap & STRING_HEAP_4 else 2
    row_size = _row_size(0x1A, context.heap, context.rows)
    offset = context.offsets[0x1A] + (row - 1) * row_size
    name_index = _read_index(context.data, offset, str_size)
    return _string_at(context.data, context.strings_base, name_index)
