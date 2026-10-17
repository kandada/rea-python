"""CLI (Common Language Infrastructure) metadata reader.

Decodes .NET metadata tables enough to recover assembly members: TypeDef and
MethodDef names (with Field/Method counts) from the ``#~`` table stream and the
``#Strings`` heap. Pure Python; the assembly is never loaded or executed.
"""

from __future__ import annotations

import mmap
import struct
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

# Column schema: ('u1'|'u2'|'u4'|'str'|'guid'|'blob'| ('idx', table) | ('coded', tables, bits))
_SIMPLE_TABLES: dict[int, list[Any]] = {
    MODULE: [("u2", None), ("str", None), ("guid", None), ("guid", None), ("guid", None)],
    TYPEREF: [("coded", (MODULE, 0x1A, 0x23, TYPEREF), 2), ("str", None), ("str", None)],
    TYPEDEF: [
        ("u4", None),
        ("str", None),
        ("str", None),
        ("coded", (TYPEDEF, TYPEREF, 0x1B), 2),
        ("idx", FIELD),
        ("idx", METHODDEF),
    ],
    FIELDPTR: [("idx", FIELD)],
    FIELD: [("u2", None), ("str", None), ("blob", None)],
    METHODPTR: [("idx", METHODDEF)],
    0x08: [("u2", None), ("u2", None), ("str", None)],  # Param
    0x09: [("idx", TYPEDEF), ("coded", (TYPEDEF, TYPEREF, 0x1B), 2)],  # InterfaceImpl
    0x0A: [
        ("coded", (TYPEDEF, TYPEREF, 0x1A, METHODDEF, 0x1B), 3),
        ("str", None),
        ("blob", None),
    ],  # MemberRef
    0x1B: [("blob", None)],  # TypeSpec
    METHODDEF: [
        ("u4", None),
        ("u2", None),
        ("u2", None),
        ("str", None),
        ("blob", None),
        ("idx", 0x08),
    ],
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


def parse_managed_members(
    data: bytes | mmap.mmap, streams: dict[str, int]
) -> dict[str, Any] | None:
    """Recover member names from the metadata table stream."""

    tables_base = streams.get("#~")
    strings_base = streams.get("#Strings")
    if tables_base is None or strings_base is None:
        return None
    if tables_base + 24 > len(data):
        return None
    heap = data[tables_base + 6]
    valid = int.from_bytes(bytes(data[tables_base + 8 : tables_base + 16]), "little")
    cursor = tables_base + 24
    rows: dict[int, int] = {}
    for index in range(64):
        if valid & (1 << index):
            rows[index] = int.from_bytes(bytes(data[cursor : cursor + 4]), "little")
            cursor += 4
    rows_start = cursor

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

    @property
    def string_size(self) -> int:
        return 4 if self.heap & STRING_HEAP_4 else 2


def load_metadata(data: bytes | mmap.mmap, streams: dict[str, int]) -> MetadataContext | None:
    """Load a context suitable for member recovery and token resolution."""

    tables_base = streams.get("#~")
    strings_base = streams.get("#Strings")
    if tables_base is None or strings_base is None or tables_base + 24 > len(data):
        return None
    heap = data[tables_base + 6]
    valid = int.from_bytes(bytes(data[tables_base + 8 : tables_base + 16]), "little")
    cursor = tables_base + 24
    rows: dict[int, int] = {}
    for index in range(64):
        if valid & (1 << index):
            rows[index] = int.from_bytes(bytes(data[cursor : cursor + 4]), "little")
            cursor += 4
    offsets: dict[int, int] = {}
    position = cursor
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
