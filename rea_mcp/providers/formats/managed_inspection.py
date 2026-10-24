"""Extended, bounded .NET/CLI metadata inspection.

The original reader only recovered TypeDef/MethodDef names. This module adds
fields, constants, signatures, nesting, member references, exported types,
module/assembly identity, CIL anchors, calls, field accesses and #US literals.
It remains a pure static reader: no assembly is loaded or executed.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import struct
import threading
from collections import OrderedDict
from collections.abc import Callable
from typing import Any

from .cil import CilError, disassemble, parse_method_body
from .cli_metadata import (
    _SIMPLE_TABLES,
    ASSEMBLY,
    ASSEMBLYREF,
    CONSTANT,
    CUSTOMATTRIBUTE,
    EXPORTEDTYPE,
    FIELD,
    FIELDPTR,
    MANIFESTRESOURCE,
    MEMBERREF,
    METHODDEF,
    METHODPTR,
    MODULE,
    MODULEREF,
    NESTEDCLASS,
    PARAM,
    PROPERTY,
    TYPEDEF,
    TYPEREF,
    TYPESPEC,
    MetadataContext,
    MetadataError,
    _read_uleb,
    load_metadata,
    resolve_token,
)

_TYPE_NAMES = {
    0x01: "void",
    0x02: "bool",
    0x03: "char",
    0x04: "int8",
    0x05: "uint8",
    0x06: "int16",
    0x07: "uint16",
    0x08: "int32",
    0x09: "uint32",
    0x0A: "int64",
    0x0B: "uint64",
    0x0C: "float32",
    0x0D: "float64",
    0x0E: "string",
    0x16: "typedref",
    0x18: "native int",
    0x19: "native uint",
    0x1C: "object",
}

_CONSTANT_TYPES = {
    0x02: "bool",
    0x03: "char",
    0x04: "int8",
    0x05: "uint8",
    0x06: "int16",
    0x07: "uint16",
    0x08: "int32",
    0x09: "uint32",
    0x0A: "int64",
    0x0B: "uint64",
    0x0C: "float32",
    0x0D: "float64",
    0x0E: "string",
    0x12: "class",
}

_CALL_OPCODES = {"call", "callvirt", "newobj", "jmp", "calli"}
_FIELD_OPCODES = {"ldfld", "ldflda", "stfld", "ldsfld", "ldsflda", "stsfld"}

_CACHE_VERSION = 1
_CACHE_LOCK = threading.RLock()
_CACHE: OrderedDict[tuple[Any, ...], dict[str, Any]] = OrderedDict()
_CACHE_HITS = 0
_CACHE_MISSES = 0


def _cache_limit() -> int:
    try:
        return max(0, int(os.environ.get("REA_MANAGED_CACHE_ENTRIES", "8")))
    except ValueError:
        return 8


def clear_managed_cache() -> None:
    global _CACHE_HITS, _CACHE_MISSES
    with _CACHE_LOCK:
        _CACHE.clear()
        _CACHE_HITS = 0
        _CACHE_MISSES = 0


def managed_cache_info() -> dict[str, int]:
    with _CACHE_LOCK:
        return {
            "entries": len(_CACHE),
            "limit": _cache_limit(),
            "hits": _CACHE_HITS,
            "misses": _CACHE_MISSES,
        }


def _read_row(context: MetadataContext, table: int, row: int) -> list[Any]:
    offset = context.row_offset(table, row)
    schema = _SIMPLE_TABLES.get(table)
    if offset is None or schema is None:
        raise MetadataError(f"table {table:#x} row {row} is unavailable")
    values: list[Any] = []
    cursor = offset
    for column in schema:
        kind = column[0]
        if kind == "u1":
            values.append(int.from_bytes(bytes(context.data[cursor : cursor + 1]), "little"))
            cursor += 1
        elif kind == "u2":
            values.append(int.from_bytes(bytes(context.data[cursor : cursor + 2]), "little"))
            cursor += 2
        elif kind == "u4":
            values.append(int.from_bytes(bytes(context.data[cursor : cursor + 4]), "little"))
            cursor += 4
        elif kind in ("str", "guid", "blob"):
            size = (
                context.string_size
                if kind == "str"
                else context.guid_size
                if kind == "guid"
                else context.blob_size
            )
            values.append(context.read_index(cursor, size))
            cursor += size
        elif kind == "idx":
            size = context.simple_size(column[1])
            values.append(context.read_index(cursor, size))
            cursor += size
        elif kind == "coded":
            size = context.coded_size(column[1], column[2])
            values.append(context.read_index(cursor, size))
            cursor += size
        else:  # pragma: no cover - schema typo guard
            raise MetadataError(f"unsupported column kind {kind!r}")
    return values


def _coded(context: MetadataContext, raw: int, tables: tuple[int, ...], bits: int) -> str | None:
    parsed = context.coded_token(raw, tables, bits)
    if parsed is None:
        return None
    return context.token(*parsed)


def _full_name(namespace: str, name: str) -> str:
    return f"{namespace}.{name}" if namespace else name


def _type_token_name(
    context: MetadataContext,
    token: str | None,
    type_names: dict[str, str],
    type_specs: dict[str, bytes],
    *,
    depth: int = 0,
) -> str | None:
    if not token or depth > 12:
        return None
    if token in type_names:
        return type_names[token]
    table = int(token, 16) >> 24
    if table != 0x1B:
        return None
    blob = type_specs.get(token)
    if blob is None:
        return None
    try:
        value, _ = _decode_type(context, blob, 0, type_names, type_specs, depth + 1)
        return value
    except (MetadataError, IndexError, struct.error):
        return "<typespec>"


def _read_compressed(context: MetadataContext, blob: bytes, offset: int) -> tuple[int, int]:
    value, cursor = _read_uleb(blob, offset)
    return value, cursor


def _decode_type(
    context: MetadataContext,
    blob: bytes,
    offset: int,
    type_names: dict[str, str],
    type_specs: dict[str, bytes],
    depth: int = 0,
) -> tuple[str, int]:
    if depth > 32 or offset >= len(blob):
        raise MetadataError("truncated type signature")
    element = blob[offset]
    offset += 1
    if element in _TYPE_NAMES:
        return _TYPE_NAMES[element], offset
    if element in (0x1F, 0x20):  # modreq / modopt
        raw, offset = _read_compressed(context, blob, offset)
        token = _coded(context, raw, (TYPEDEF, TYPEREF, TYPESPEC), 2)
        _ = token
        return _decode_type(context, blob, offset, type_names, type_specs, depth + 1)
    if element == 0x0F:  # pointer
        inner, offset = _decode_type(context, blob, offset, type_names, type_specs, depth + 1)
        return inner + "*", offset
    if element == 0x10:  # byref
        inner, offset = _decode_type(context, blob, offset, type_names, type_specs, depth + 1)
        return inner + "&", offset
    if element in (0x11, 0x12):  # valuetype / class
        raw, offset = _read_compressed(context, blob, offset)
        token = _coded(context, raw, (TYPEDEF, TYPEREF, TYPESPEC), 2)
        name = _type_token_name(context, token, type_names, type_specs, depth=depth + 1)
        return name or (token or "<type>"), offset
    if element == 0x13:  # var
        index, offset = _read_compressed(context, blob, offset)
        return f"!{index}", offset
    if element == 0x1E:  # mvar
        index, offset = _read_compressed(context, blob, offset)
        return f"!!{index}", offset
    if element == 0x14:  # array
        inner, offset = _decode_type(context, blob, offset, type_names, type_specs, depth + 1)
        rank, offset = _read_compressed(context, blob, offset)
        for _ in range(rank):
            _, offset = _read_compressed(context, blob, offset)
        for _ in range(rank):
            _, offset = _read_compressed(context, blob, offset)
        return f"{inner}[{',' * max(0, rank - 1)}]", offset
    if element == 0x15:  # genericinst
        kind = blob[offset]
        offset += 1
        raw, offset = _read_compressed(context, blob, offset)
        token = _coded(context, raw, (TYPEDEF, TYPEREF, TYPESPEC), 2)
        base = _type_token_name(context, token, type_names, type_specs, depth=depth + 1)
        count, offset = _read_compressed(context, blob, offset)
        arguments = []
        for _ in range(count):
            argument, offset = _decode_type(
                context, blob, offset, type_names, type_specs, depth + 1
            )
            arguments.append(argument)
        prefix = "valuetype" if kind == 0x11 else "class"
        return f"{prefix} {base or '<type>'}<{', '.join(arguments)}>", offset
    if element == 0x1D:  # szarray
        inner, offset = _decode_type(context, blob, offset, type_names, type_specs, depth + 1)
        return inner + "[]", offset
    if element == 0x1B:  # fnptr
        signature, offset = _decode_method_signature(
            context, blob, offset, type_names, type_specs, depth + 1
        )
        return f"fnptr {signature['return_type'] or 'unknown'}(...)", offset
    if element == 0x45:  # pinned
        return _decode_type(context, blob, offset, type_names, type_specs, depth + 1)
    raise MetadataError(f"unsupported element type {element:#x}")


def _calling_convention(first: int) -> str:
    value = first & 0x0F
    return {
        0x00: "default",
        0x01: "cdecl",
        0x02: "stdcall",
        0x03: "thiscall",
        0x04: "fastcall",
        0x05: "vararg",
    }.get(value, f"0x{value:02x}")


def _decode_method_signature(
    context: MetadataContext,
    blob: bytes,
    offset: int,
    type_names: dict[str, str],
    type_specs: dict[str, bytes],
    depth: int = 0,
) -> tuple[dict[str, Any], int]:
    first = blob[offset]
    offset += 1
    generic_count: int | None = None
    if first & 0x10:
        generic_count, offset = _read_compressed(context, blob, offset)
    parameter_count, offset = _read_compressed(context, blob, offset)
    return_type, offset = _decode_type(context, blob, offset, type_names, type_specs, depth + 1)
    parameters = []
    for _ in range(parameter_count):
        parameter, offset = _decode_type(context, blob, offset, type_names, type_specs, depth + 1)
        parameters.append(parameter)
    return {
        "kind": "method",
        "parse_status": "decoded",
        "calling_convention": _calling_convention(first),
        "generic_parameter_count": generic_count,
        "parameter_count": parameter_count,
        "return_type": return_type,
        "parameter_types": parameters,
        "field_type": None,
        "issue": None,
    }, offset


def _decode_signature(
    context: MetadataContext,
    raw: bytes,
    type_names: dict[str, str],
    type_specs: dict[str, bytes],
) -> dict[str, Any]:
    raw_sha = hashlib.sha256(raw).hexdigest()
    result: dict[str, Any] = {
        "raw_length": len(raw),
        "raw_sha256": raw_sha,
        "resolved_sha256": None,
        "kind": "unknown",
        "parse_status": "malformed",
        "calling_convention": None,
        "generic_parameter_count": None,
        "parameter_count": None,
        "return_type": None,
        "parameter_types": [],
        "field_type": None,
        "issue": None,
    }
    if not raw:
        result["issue"] = "empty signature"
        return result
    try:
        if raw[0] == 0x06:  # field
            value, _ = _decode_type(context, raw, 1, type_names, type_specs)
            result.update(
                {
                    "kind": "field",
                    "parse_status": "decoded",
                    "field_type": value,
                }
            )
            return result
        method, _ = _decode_method_signature(context, raw, 0, type_names, type_specs)
        result.update(method)
        return result
    except (MetadataError, IndexError, struct.error) as cause:
        result["issue"] = str(cause)
        return result


def _decode_constant(kind: int, raw: bytes) -> Any:
    if kind == 0x12:
        return None
    if kind == 0x0E:
        return raw.decode("utf-16-le", errors="replace")
    formats: dict[int, tuple[str, int]] = {
        0x02: ("<?", 1),
        0x03: ("<H", 2),
        0x04: ("<b", 1),
        0x05: ("<B", 1),
        0x06: ("<h", 2),
        0x07: ("<H", 2),
        0x08: ("<i", 4),
        0x09: ("<I", 4),
        0x0A: ("<q", 8),
        0x0B: ("<Q", 8),
        0x0C: ("<f", 4),
        0x0D: ("<d", 8),
    }
    fmt = formats.get(kind)
    if fmt is None:
        return raw.hex()
    pattern, size = fmt
    if len(raw) < size:
        return None
    value = struct.unpack_from(pattern, raw)[0]
    if kind == 0x02:
        return bool(value)
    if kind == 0x03:
        return chr(value)
    return value


def _member_rows(
    context: MetadataContext, pointer_table: int, target_table: int, count: int
) -> list[int]:
    if context.row_count(pointer_table) > 0:
        rows = []
        for row in range(1, context.row_count(pointer_table) + 1):
            values = _read_row(context, pointer_table, row)
            rows.append(int(values[0]))
        return rows
    return list(range(1, count + 1))


def _type_ranges(
    context: MetadataContext,
    types: list[dict[str, Any]],
    field_rows: list[int],
    method_rows: list[int],
) -> None:
    for index, type_entry in enumerate(types):
        next_entry = types[index + 1] if index + 1 < len(types) else None
        for key, _table, rows, pointer_table in (
            ("field_list", FIELD, field_rows, FIELDPTR),
            ("method_list", METHODDEF, method_rows, METHODPTR),
        ):
            start = int(type_entry[key] or 1)
            end = int(next_entry[key] or (len(rows) + 1)) if next_entry else len(rows) + 1
            if pointer_table and context.row_count(pointer_table) > 0:
                selected = rows[max(0, start - 1) : max(0, end - 1)]
            else:
                selected = list(range(max(1, start), max(1, end)))
            type_entry[key] = {
                "first_row": selected[0] if selected else None,
                "last_row": selected[-1] if selected else None,
                "count": len(selected),
            }
            type_entry["_field_rows" if key == "field_list" else "_method_rows"] = selected


def _load_identity(
    context: MetadataContext,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, list[dict[str, Any]]]:
    module = None
    assembly = None
    references: list[dict[str, Any]] = []
    if context.row_count(MODULE):
        values = _read_row(context, MODULE, 1)
        module = {
            "name": context.read_string(int(values[1])),
            "mvid": context.read_guid(int(values[2])),
        }
    if context.row_count(ASSEMBLY):
        values = _read_row(context, ASSEMBLY, 1)
        assembly = {
            "name": context.read_string(int(values[7])),
            "version": f"{values[1]}.{values[2]}.{values[3]}.{values[4]}",
            "culture": context.read_string(int(values[8])) or None,
            "flags": values[5],
        }
    for row in range(1, context.row_count(ASSEMBLYREF) + 1):
        values = _read_row(context, ASSEMBLYREF, row)
        references.append(
            {
                "token": context.token(ASSEMBLYREF, row),
                "name": context.read_string(int(values[6])),
                "version": f"{values[0]}.{values[1]}.{values[2]}.{values[3]}",
                "culture": context.read_string(int(values[7])) or None,
            }
        )
    return module, assembly, references


def _load_manifest(
    context: MetadataContext,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    resources: list[dict[str, Any]] = []
    attributes: list[dict[str, Any]] = []
    for row in range(1, context.row_count(MANIFESTRESOURCE) + 1):
        values = _read_row(context, MANIFESTRESOURCE, row)
        implementation = _coded(context, int(values[3]), (0x26, 0x23, 0x27), 2)
        resources.append(
            {
                "token": context.token(MANIFESTRESOURCE, row),
                "name": context.read_string(int(values[2])),
                "offset": int(values[0]),
                "flags": int(values[1]),
                "implementation_token": implementation,
            }
        )
    for row in range(1, context.row_count(CUSTOMATTRIBUTE) + 1):
        values = _read_row(context, CUSTOMATTRIBUTE, row)
        parent = _coded(
            context,
            int(values[0]),
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
                0x2B,
                0x2C,
            ),
            5,
        )
        constructor = _coded(context, int(values[1]), (0x06, 0x0A), 3)
        attributes.append(
            {
                "token": context.token(CUSTOMATTRIBUTE, row),
                "parent_token": parent,
                "constructor_token": constructor,
                "value_length": len(context.read_blob(int(values[2]))),
            }
        )
    return resources, attributes


def _operand_kind(opcode: str, operand: Any) -> str:
    if opcode == "switch":
        return "switch"
    if isinstance(operand, str) and operand.startswith("0x"):
        table = int(operand, 16) >> 24
        if opcode == "ldstr" or table == 0x70:
            return "string"
        if table == 0x04 or opcode in _FIELD_OPCODES:
            return "field"
        if table in (0x06, 0x0A, 0x2B) or opcode in _CALL_OPCODES:
            return "method"
        if table in (0x01, 0x02, 0x1B, 0x11):
            return "type"
        return "token"
    if isinstance(operand, int):
        if opcode.startswith(("br", "leave", "beq", "bge", "bgt", "ble", "blt", "bne")):
            return "branch"
        if opcode.startswith(("ldc", "ldarg", "ldloc", "starg", "stloc")):
            return (
                "variable"
                if opcode.startswith(("ldarg", "ldloc", "starg", "stloc"))
                else "constant"
            )
    if opcode.startswith("ldc"):
        return "constant"
    return "none"


def _body(
    context: MetadataContext,
    method: dict[str, Any],
    rva_to_offset: Callable[[int], int | None] | None,
    type_names: dict[str, str],
    type_specs: dict[str, bytes],
    fields_by_token: dict[str, dict[str, Any]],
    method_owner: dict[str, str],
) -> tuple[
    dict[str, Any],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    rva = int(method["rva"])
    body: dict[str, Any] = {
        "status": "absent",
        "header_format": "none",
        "rva": rva,
        "file_offset": None,
        "max_stack": None,
        "init_locals": None,
        "local_var_sig_token": None,
        "il_size": 0,
        "il_sha256": None,
        "normalized_il_sha256": None,
        "instruction_count": 0,
        "decoded_instruction_count": 0,
        "truncated_instructions": 0,
        "anchors": [],
        "exception_regions": [],
        "issue": None,
    }
    calls: list[dict[str, Any]] = []
    accesses: list[dict[str, Any]] = []
    strings: list[dict[str, Any]] = []
    initializers: list[dict[str, Any]] = []
    if rva == 0 or rva_to_offset is None:
        return body, calls, accesses, strings, initializers
    offset = rva_to_offset(rva)
    if offset is None:
        body.update(status="malformed", issue="method body RVA is outside the image")
        return body, calls, accesses, strings, initializers
    try:
        header, code = parse_method_body(context.data, offset)
        instructions = disassemble(code)
    except (CilError, IndexError, struct.error) as cause:
        body.update(status="malformed", issue=str(cause))
        return body, calls, accesses, strings, initializers
    anchors: list[dict[str, Any]] = []
    tuples: list[list[Any]] = []
    last_constant: Any = None
    for instruction in instructions:
        opcode = str(instruction.get("opcode"))
        operand = instruction.get("operand")
        kind = _operand_kind(opcode, operand)
        anchor = {
            "il_offset": int(instruction.get("offset") or 0),
            "opcode": opcode,
            "operand_kind": kind,
            "operand": operand,
        }
        resolved = None
        if isinstance(operand, str) and operand.startswith("0x"):
            resolved = resolve_token(context, int(operand, 16))
            if resolved:
                anchor["resolved"] = resolved
        if opcode == "ldstr":
            last_constant = resolved
        elif opcode.startswith("ldc."):
            last_constant = operand
        elif opcode == "ldnull":
            last_constant = None
        anchors.append(anchor)
        tuples.append([opcode, kind, operand])
        if isinstance(operand, str) and operand.startswith("0x"):
            token = int(operand, 16)
            table = token >> 24
            row = token & 0xFFFFFF
            if opcode in _CALL_OPCODES:
                target = resolve_token(context, token) or context.row_label(table, row)
                calls.append(
                    {
                        "caller_token": method["token"],
                        "caller": method["name"],
                        "opcode": opcode,
                        "target_token": operand,
                        "target_kind": {
                            0x06: "method-def",
                            0x0A: "member-ref",
                            0x2B: "method-spec",
                        }.get(table, "unknown"),
                        "target_name": target,
                        "target_declaring_type": (
                            fields_by_token.get(operand, {}).get("declaring_type")
                            if table == 0x04
                            else method_owner.get(operand)
                        ),
                    }
                )
            elif opcode in _FIELD_OPCODES or table == 0x04:
                field = fields_by_token.get(operand)
                accesses.append(
                    {
                        "method_token": method["token"],
                        "method": method["name"],
                        "opcode": opcode,
                        "field_token": operand,
                        "field_name": field.get("name") if field else resolve_token(context, token),
                        "field_declaring_type": field.get("declaring_type") if field else None,
                    }
                )
            elif opcode == "ldstr" or table == 0x70:
                value = resolve_token(context, token)
                if value is not None:
                    strings.append(
                        {
                            "token": operand,
                            "offset": (context.us_base or 0) + row,
                            "value": value,
                        }
                    )
        if opcode == "stsfld" and isinstance(operand, str):
            field = fields_by_token.get(operand)
            initializers.append(
                {
                    "method_token": method["token"],
                    "method": method["name"],
                    "field_token": operand,
                    "field_name": (
                        field.get("name") if field else resolve_token(context, int(operand, 16))
                    ),
                    "field_declaring_type": field.get("declaring_type") if field else None,
                    "value": last_constant,
                }
            )
    body.update(
        {
            "status": "present",
            "header_format": header.get("format", "unknown"),
            "file_offset": offset,
            "max_stack": header.get("max_stack"),
            "il_size": len(code),
            "il_sha256": hashlib.sha256(code).hexdigest(),
            "normalized_il_sha256": hashlib.sha256(
                json.dumps(tuples, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            ).hexdigest(),
            "instruction_count": len(instructions),
            "decoded_instruction_count": len(instructions),
            "anchors": anchors,
        }
    )
    return body, calls, accesses, strings, initializers


def parse_managed_inspection(
    data: bytes,
    streams: dict[str, int],
    *,
    stream_sizes: dict[str, int] | None = None,
    runtime_version: str | None = None,
    rva_to_offset: Callable[[int], int | None] | None = None,
    type_names: list[str] | None = None,
    detail: str = "complete",
    include_fields: bool = True,
    include_methods: bool = True,
    include_constants: bool = True,
    include_member_refs: bool = True,
    include_exported_types: bool = True,
    include_user_strings: bool = True,
    include_bodies: bool | None = None,
    include_edges: bool = True,
) -> dict[str, Any]:
    """Parse managed metadata into a practical inspection projection."""

    global _CACHE_HITS, _CACHE_MISSES
    cache_key = (
        _CACHE_VERSION,
        hashlib.sha256(bytes(data)).hexdigest(),
        runtime_version,
        tuple(type_names) if type_names is not None else None,
        detail,
        include_fields,
        include_methods,
        include_constants,
        include_member_refs,
        include_exported_types,
        include_user_strings,
        include_bodies,
        include_edges,
        rva_to_offset is not None,
    )
    limit = _cache_limit()
    if limit:
        with _CACHE_LOCK:
            cached = _CACHE.get(cache_key)
            if cached is not None:
                _CACHE.move_to_end(cache_key)
                _CACHE_HITS += 1
                return copy.deepcopy(cached)
    context = load_metadata(data, streams, stream_sizes)
    if context is None:
        raise MetadataError("CLI metadata tables could not be decoded")

    # TypeDef and TypeRef names are needed by signatures and edges.
    type_rows = [
        _read_row(context, TYPEDEF, row) for row in range(1, context.row_count(TYPEDEF) + 1)
    ]
    type_ref_rows = [
        _read_row(context, TYPEREF, row) for row in range(1, context.row_count(TYPEREF) + 1)
    ]
    type_spec_rows = [
        _read_row(context, TYPESPEC, row) for row in range(1, context.row_count(TYPESPEC) + 1)
    ]
    type_specs = {
        context.token(TYPESPEC, row): context.read_blob(int(values[0]))
        for row, values in enumerate(type_spec_rows, 1)
    }
    type_name_map: dict[str, str] = {}
    for row, values in enumerate(type_ref_rows, 1):
        type_name_map[context.token(TYPEREF, row)] = _full_name(
            context.read_string(int(values[2])), context.read_string(int(values[1]))
        )

    nested: dict[int, int] = {}
    nested_complete = True
    for row in range(1, context.row_count(NESTEDCLASS) + 1):
        values = _read_row(context, NESTEDCLASS, row)
        nested[int(values[0])] = int(values[1])

    def type_full_name(row: int, seen: set[int]) -> str:
        nonlocal nested_complete
        values = type_rows[row - 1]
        namespace = context.read_string(int(values[2]))
        name = context.read_string(int(values[1]))
        if row in nested and row not in seen and len(seen) < 32:
            outer = nested[row]
            if 1 <= outer <= len(type_rows):
                return f"{type_full_name(outer, seen | {row})}+{name}"
            nested_complete = False
        return _full_name(namespace, name)

    types: list[dict[str, Any]] = []
    for row, values in enumerate(type_rows, 1):
        namespace = context.read_string(int(values[2]))
        name = context.read_string(int(values[1]))
        extends = _coded(context, int(values[3]), (TYPEDEF, TYPEREF, TYPESPEC), 2)
        full = type_full_name(row, set())
        type_name_map[context.token(TYPEDEF, row)] = full
        types.append(
            {
                "token": context.token(TYPEDEF, row),
                "row_offset": context.row_offset(TYPEDEF, row),
                "namespace": namespace,
                "name": name,
                "full_name": full,
                "name_sha256": hashlib.sha256(
                    (namespace + "\x00" + name + "\x00" + full).encode("utf-8")
                ).hexdigest(),
                "flags": int(values[0]),
                "extends_token": extends,
                "enclosing_type_token": (
                    context.token(TYPEDEF, nested[row]) if row in nested else None
                ),
                "field_list": int(values[4]),
                "method_list": int(values[5]),
            }
        )

    field_rows = _member_rows(context, FIELDPTR, FIELD, context.row_count(FIELD))
    method_rows = _member_rows(context, METHODPTR, METHODDEF, context.row_count(METHODDEF))
    _type_ranges(context, types, field_rows, method_rows)

    selected_tokens: set[str] | None = None
    selection = None
    if type_names is not None:
        requested = list(dict.fromkeys(type_names))
        requested_set = set(requested)
        selected_tokens = set()
        matched: set[str] = set()
        for entry in types:
            if entry["full_name"] in requested_set:
                selected_tokens.add(entry["token"])
                matched.add(entry["full_name"])
            elif entry.get("enclosing_type_token") and entry["name"] in requested_set:
                selected_tokens.add(entry["token"])
                matched.add(entry["name"])
        selection = {
            "type_names": requested,
            "unmatched_type_names": [name for name in requested if name not in matched],
        }

    selected_types = [
        entry for entry in types if selected_tokens is None or entry["token"] in selected_tokens
    ]

    # Constants are keyed by their Field token.
    field_constants: dict[str, dict[str, Any]] = {}
    constant_count = context.row_count(CONSTANT)
    if include_constants:
        for row in range(1, constant_count + 1):
            values = _read_row(context, CONSTANT, row)
            parent = context.coded_token(int(values[1]), (FIELD, PARAM, PROPERTY), 2)
            if parent is None or parent[0] != FIELD:
                continue
            kind = int(values[0])
            raw = context.read_blob(int(values[2]))
            field_constants[context.token(FIELD, parent[1])] = {
                "type": _CONSTANT_TYPES.get(kind, f"0x{kind:02x}"),
                "value": _decode_constant(kind, raw),
            }

    fields_by_token: dict[str, dict[str, Any]] = {}
    fields: list[dict[str, Any]] = []
    method_owner: dict[str, str] = {}
    field_owner: dict[str, str] = {}
    for entry in types:
        for field_row in entry.get("_field_rows", []):
            field_owner[context.token(FIELD, field_row)] = entry["full_name"]
        for method_row in entry.get("_method_rows", []):
            method_owner[context.token(METHODDEF, method_row)] = entry["full_name"]

    for row in range(1, context.row_count(FIELD) + 1):
        values = _read_row(context, FIELD, row)
        token = context.token(FIELD, row)
        owner = field_owner.get(token)
        if owner is None:
            continue
        if selected_tokens is not None and not any(
            entry["full_name"] == owner and entry["token"] in selected_tokens
            for entry in selected_types
        ):
            continue
        raw = context.read_blob(int(values[2]))
        item: dict[str, Any] = {
            "token": token,
            "row_offset": context.row_offset(FIELD, row),
            "declaring_type_token": next(
                (entry["token"] for entry in selected_types if entry["full_name"] == owner),
                None,
            ),
            "declaring_type": owner,
            "name": context.read_string(int(values[1])),
            "flags": int(values[0]),
            "signature": _decode_signature(context, raw, type_name_map, type_specs),
        }
        if token in field_constants:
            item["constant"] = field_constants[token]["value"]
            item["constant_type"] = field_constants[token]["type"]
        fields_by_token[token] = item
        if include_fields:
            fields.append(item)

    include_bodies = bool(type_names) if include_bodies is None else include_bodies
    if detail == "summary" or not include_methods:
        include_bodies = False

    methods: list[dict[str, Any]] = []
    methods_by_type: dict[str, list[dict[str, Any]]] = {}
    call_edges: list[dict[str, Any]] = []
    field_accesses: list[dict[str, Any]] = []
    field_initializers: list[dict[str, Any]] = []
    user_strings: list[dict[str, Any]] = []
    user_string_state = "complete"
    for row in range(1, context.row_count(METHODDEF) + 1) if include_methods else ():
        values = _read_row(context, METHODDEF, row)
        token = context.token(METHODDEF, row)
        owner = method_owner.get(token)
        if owner is None:
            continue
        owner_entry = next((entry for entry in selected_types if entry["full_name"] == owner), None)
        if owner_entry is None:
            continue
        raw = context.read_blob(int(values[4]))
        method: dict[str, Any] = {
            "token": token,
            "row_offset": context.row_offset(METHODDEF, row),
            "declaring_type_token": owner_entry["token"],
            "declaring_type": owner,
            "name": context.read_string(int(values[3])),
            "rva": int(values[0]),
            "impl_flags": int(values[1]),
            "flags": int(values[2]),
            "signature": _decode_signature(context, raw, type_name_map, type_specs),
            "body": {
                "status": "absent",
                "header_format": "none",
                "rva": int(values[0]),
                "file_offset": None,
                "il_size": 0,
                "il_sha256": None,
                "normalized_il_sha256": None,
                "instruction_count": 0,
                "decoded_instruction_count": 0,
                "anchors": [],
                "exception_regions": [],
                "issue": None,
            },
        }
        if include_bodies:
            body, calls, accesses, strings, initializers = _body(
                context,
                method,
                rva_to_offset,
                type_name_map,
                type_specs,
                fields_by_token,
                method_owner,
            )
            method["body"] = body
            if include_edges:
                call_edges.extend(calls)
                field_accesses.extend(accesses)
                field_initializers.extend(initializers)
            if include_user_strings:
                user_strings.extend(strings)
        methods.append(method)
        methods_by_type.setdefault(owner, []).append(method)

    for entry in selected_types:
        entry["methods"] = methods_by_type.get(entry["full_name"], [])
        entry["methods_total"] = len(entry["methods"])
        entry["methods_offset"] = 0
        entry["methods_next_offset"] = None
        entry["fields_total"] = sum(
            1 for item in fields if item["declaring_type"] == entry["full_name"]
        )

    member_refs: list[dict[str, Any]] = []
    if include_member_refs:
        parent_tables = (TYPEDEF, TYPEREF, MODULEREF, METHODDEF, TYPESPEC)
        for row in range(1, context.row_count(MEMBERREF) + 1):
            values = _read_row(context, MEMBERREF, row)
            parent_token = _coded(context, int(values[0]), parent_tables, 3)
            parent_name = None
            if parent_token:
                table = int(parent_token, 16) >> 24
                row_index = int(parent_token, 16) & 0xFFFFFF
                parent_name = context.row_label(table, row_index)
            member_refs.append(
                {
                    "token": context.token(MEMBERREF, row),
                    "row_offset": context.row_offset(MEMBERREF, row),
                    "parent_token": parent_token,
                    "parent_name": parent_name,
                    "name": context.read_string(int(values[1])),
                    "signature": _decode_signature(
                        context, context.read_blob(int(values[2])), type_name_map, type_specs
                    ),
                }
            )

    exported_types: list[dict[str, Any]] | None = None
    if include_exported_types:
        exported_types = []
        for row in range(1, context.row_count(EXPORTEDTYPE) + 1):
            values = _read_row(context, EXPORTEDTYPE, row)
            flags = int(values[0])
            implementation = _coded(context, int(values[4]), (0x26, 0x23, 0x27), 2)
            exported_types.append(
                {
                    "token": context.token(EXPORTEDTYPE, row),
                    "row_offset": context.row_offset(EXPORTEDTYPE, row),
                    "namespace": context.read_string(int(values[3])),
                    "name": context.read_string(int(values[2])),
                    "flags": flags,
                    "forwarder": bool(flags & 0x00200000),
                    "type_def_id": int(values[1]),
                    "implementation_token": implementation,
                }
            )

    module, assembly, references = _load_identity(context)
    resources, attributes = _load_manifest(context)

    # De-duplicate #US literals while keeping token order.
    seen_strings: set[str] = set()
    unique_strings = []
    for item in user_strings:
        if item["token"] in seen_strings:
            continue
        seen_strings.add(item["token"])
        unique_strings.append(item)

    if not include_bodies:
        user_string_state = "partial"
    for entry in types:
        entry.pop("_field_rows", None)
        entry.pop("_method_rows", None)
    type_total = len(selected_types)
    field_total = len(fields)
    method_total = len(methods)
    member_ref_total = len(member_refs)
    exported_total = len(exported_types) if exported_types is not None else None
    call_total = len(call_edges)
    access_total = len(field_accesses)
    initializer_total = len(field_initializers)
    string_total = len(unique_strings) if include_bodies and include_user_strings else None
    summary = detail == "summary"
    result: dict[str, Any] = {
        "module": module,
        "assembly": assembly,
        "references": references,
        "metadata": {
            "status": "complete",
            "version": runtime_version,
            "table_row_counts": {
                _table_name(index): count for index, count in sorted(context.rows.items())
            },
            "streams": sorted(streams.keys()),
            "tables_stream": context.tables_name,
        },
        "identity_scope": {
            "token_identity": "build-local",
            "requires_artifact_sha256": None,
            "requires_mvid": module.get("mvid") if module else None,
        },
        "type_count": context.row_count(TYPEDEF),
        "method_count": context.row_count(METHODDEF),
        "field_count": context.row_count(FIELD),
        "member_ref_count": member_ref_total,
        "exported_type_count": exported_total,
        "nesting_read": nested_complete,
        "selection": selection,
        "types": [] if summary else selected_types,
        "fields": [] if summary or not include_fields else fields,
        "methods": [] if summary else methods,
        "member_refs": [] if summary else member_refs,
        "exported_types": [] if summary else exported_types,
        "call_edges": [] if summary or not include_edges else call_edges,
        "field_accesses": [] if summary or not include_edges else field_accesses,
        "field_initializers": [] if summary or not include_edges else field_initializers,
        "user_strings": (
            None
            if summary
            else (
                {"state": user_string_state, "literals": unique_strings, "issues": []}
                if include_user_strings and include_bodies
                else None
            )
        ),
        "resources": resources,
        "attributes": attributes,
        "reported_counts": {
            "types": type_total,
            "fields": field_total,
            "methods": method_total,
            "member_refs": member_ref_total,
            "exported_types": exported_total,
            "call_edges": call_total,
            "field_accesses": access_total,
            "field_initializers": initializer_total,
            "user_strings": string_total,
        },
        "coverage": {"state": "complete", "issues": []},
        "limitations": [
            "Metadata tokens are build-local and bound to the recorded artifact SHA-256/MVID.",
            "Constant values cover literal (const) fields; static readonly initialization may require CIL data-flow.",
        ]
        + (
            []
            if include_bodies
            else [
                "Method bodies, call edges, field accesses and user strings were not decoded; select type_names or include_bodies to inspect them."
            ]
        ),
    }
    if limit:
        with _CACHE_LOCK:
            _CACHE[cache_key] = copy.deepcopy(result)
            _CACHE.move_to_end(cache_key)
            while len(_CACHE) > limit:
                _CACHE.popitem(last=False)
            _CACHE_MISSES += 1
    return result


_TABLE_NAMES = {
    0x00: "Module",
    0x01: "TypeRef",
    0x02: "TypeDef",
    0x03: "FieldPtr",
    0x04: "Field",
    0x05: "MethodPtr",
    0x06: "MethodDef",
    0x07: "ParamPtr",
    0x08: "Param",
    0x09: "InterfaceImpl",
    0x0A: "MemberRef",
    0x0B: "Constant",
    0x0C: "CustomAttribute",
    0x0D: "FieldMarshal",
    0x0E: "DeclSecurity",
    0x0F: "ClassLayout",
    0x10: "FieldLayout",
    0x11: "StandAloneSig",
    0x12: "EventMap",
    0x13: "EventPtr",
    0x14: "Event",
    0x15: "PropertyMap",
    0x16: "PropertyPtr",
    0x17: "Property",
    0x18: "MethodSemantics",
    0x19: "MethodImpl",
    0x1A: "ModuleRef",
    0x1B: "TypeSpec",
    0x1C: "ImplMap",
    0x1D: "FieldRVA",
    0x20: "Assembly",
    0x21: "AssemblyProcessor",
    0x22: "AssemblyOS",
    0x23: "AssemblyRef",
    0x24: "AssemblyRefProcessor",
    0x25: "AssemblyRefOS",
    0x26: "File",
    0x27: "ExportedType",
    0x28: "ManifestResource",
    0x29: "NestedClass",
    0x2A: "GenericParam",
    0x2B: "MethodSpec",
    0x2C: "GenericParamConstraint",
}


def _table_name(index: int) -> str:
    return _TABLE_NAMES.get(index, f"Table{index:#x}")


def summarize_managed_inspection(result: dict[str, Any]) -> dict[str, Any]:
    """Project a complete managed inspection into a compact linked summary."""

    user_strings = result.get("user_strings")
    counts = dict(result.get("reported_counts") or {})
    return {
        "kind": "managed-member-summary",
        "evidence_id": result.get("evidence_id"),
        "parent_evidence_id": result.get("evidence_id"),
        "artifact": result.get("artifact"),
        "module": result.get("module"),
        "metadata": result.get("metadata"),
        "identity_scope": result.get("identity_scope"),
        "selection": result.get("selection"),
        "nesting_read": result.get("nesting_read"),
        "signature_resolution": result.get("signature_resolution"),
        "user_strings": (
            None
            if user_strings is None
            else {
                "state": user_strings.get("state"),
                "issues": user_strings.get("issues", []),
            }
        ),
        "coverage": result.get("coverage"),
        "limitations": result.get("limitations", []),
        "reported_counts": {
            **counts,
            "field_initializers": (result.get("reported_counts") or {}).get(
                "field_initializers", 0
            ),
        },
    }


__all__ = [
    "clear_managed_cache",
    "managed_cache_info",
    "parse_managed_inspection",
    "summarize_managed_inspection",
]
