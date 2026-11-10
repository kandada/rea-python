"""Static readers absorbed from upstream REA 6.8.

PE native directories, GameCube/Wii DOL, flattened device trees, protobuf
bodies, and packaged-application markers. All readers are bounded and do not
execute the target.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
from pathlib import Path
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .formats.pe import PeInfo, parse_pe
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(
    id="upstream68", name="REA-Python upstream 6.8 static readers", version="1"
)
_OPERATIONS = (
    "inspect_pe_native_metadata",
    "inspect_dol_executable",
    "inspect_flattened_devicetree",
    "inspect_protobuf_body",
    "inspect_packaged_application",
)
_MAX_ITEMS = 500


def _cstring(data: bytes, offset: int, limit: int = 512) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\0", offset, min(len(data), offset + limit))
    if end < 0:
        end = min(len(data), offset + limit)
    return data[offset:end].decode("utf-8", errors="replace")


def _rva_offset(info: PeInfo, rva: int) -> int | None:
    for section in info.sections:
        size = max(section.virtual_size, section.size_of_raw_data)
        if section.virtual_address <= rva < section.virtual_address + size:
            delta = rva - section.virtual_address
            if delta >= section.size_of_raw_data:
                return None
            return section.pointer_to_raw_data + delta
    return None


def _pe_imports(data: bytes, info: PeInfo) -> tuple[list[dict[str, Any]], list[str]]:
    limitations: list[str] = []
    if len(info.data_directories) <= 1:
        return [], limitations
    rva, size = info.data_directories[1]
    offset = _rva_offset(info, rva)
    if offset is None or size == 0:
        return [], limitations
    rows = []
    ptr_size = 8 if info.is_pe32_plus else 4
    for index in range(_MAX_ITEMS):
        base = offset + index * 20
        if base + 20 > len(data):
            limitations.append("Import directory is truncated.")
            break
        original, timestamp, forwarder, name_rva, first = struct.unpack_from("<IIIII", data, base)
        if not any((original, timestamp, forwarder, name_rva, first)):
            break
        name_offset = _rva_offset(info, name_rva)
        dll = _cstring(data, name_offset) if name_offset is not None else ""
        functions = []
        thunk_rva = original or first
        thunk_offset = _rva_offset(info, thunk_rva)
        if thunk_offset is not None:
            for entry_index in range(_MAX_ITEMS):
                entry_offset = thunk_offset + entry_index * ptr_size
                if entry_offset + ptr_size > len(data):
                    break
                value = struct.unpack_from("<Q" if ptr_size == 8 else "<I", data, entry_offset)[0]
                if value == 0:
                    break
                if value & (1 << (ptr_size * 8 - 1)):
                    functions.append({"ordinal": value & 0xFFFF})
                else:
                    hint_offset = _rva_offset(info, value)
                    if hint_offset is not None and hint_offset + 2 < len(data):
                        hint = struct.unpack_from("<H", data, hint_offset)[0]
                        functions.append({"hint": hint, "name": _cstring(data, hint_offset + 2)})
        rows.append({"dll": dll, "functions": functions[:200], "timestamp": timestamp})
    return rows, limitations


def _pe_delay(data: bytes, info: PeInfo) -> list[dict[str, Any]]:
    if len(info.data_directories) <= 13:
        return []
    rva, size = info.data_directories[13]
    offset = _rva_offset(info, rva)
    if offset is None or size == 0:
        return []
    rows = []
    for index in range(_MAX_ITEMS):
        base = offset + index * 32
        if base + 32 > len(data):
            break
        values = struct.unpack_from("<IIIIIIII", data, base)
        if not any(values):
            break
        name_offset = _rva_offset(info, values[1])
        rows.append(
            {
                "dll": _cstring(data, name_offset) if name_offset is not None else "",
                "attributes": values[0],
                "iat_rva": values[3],
                "int_rva": values[4],
                "timestamp": values[7],
            }
        )
    return rows


def _pe_tls(data: bytes, info: PeInfo) -> dict[str, Any] | None:
    if len(info.data_directories) <= 9:
        return None
    rva, size = info.data_directories[9]
    offset = _rva_offset(info, rva)
    if offset is None or size == 0:
        return None
    ptr = 8 if info.is_pe32_plus else 4
    fmt = "<QQQQII" if info.is_pe32_plus else "<IIIIII"
    if offset + struct.calcsize(fmt) > len(data):
        return None
    values = struct.unpack_from(fmt, data, offset)
    callback_va = values[3]
    callbacks: list[str] = []
    callback_rva = callback_va - info.image_base if info.image_base else callback_va
    callback_offset = _rva_offset(info, callback_rva)
    if callback_offset is not None:
        for index in range(_MAX_ITEMS):
            entry = callback_offset + index * ptr
            if entry + ptr > len(data):
                break
            value = struct.unpack_from("<Q" if ptr == 8 else "<I", data, entry)[0]
            if value == 0:
                break
            callbacks.append(hex(value))
    return {
        "address_of_callbacks": hex(callback_va),
        "callbacks": callbacks,
        "raw": list(values[:4]),
    }


def _pe_load_config(data: bytes, info: PeInfo) -> dict[str, Any] | None:
    if len(info.data_directories) <= 10:
        return None
    rva, size = info.data_directories[10]
    offset = _rva_offset(info, rva)
    if offset is None or size == 0:
        return None
    extended = info.is_pe32_plus
    security = offset + (88 if extended else 60)
    handler_table = offset + (96 if extended else 64)
    handler_count = offset + (104 if extended else 68)
    guard_table = offset + (128 if extended else 80)
    guard_count = offset + (136 if extended else 84)
    guard_flags = offset + (144 if extended else 88)
    result: dict[str, Any] = {"size": size}
    for key, position, width in (
        ("security_cookie", security, 8 if extended else 4),
        ("seh_handler_table", handler_table, 8 if extended else 4),
        ("seh_handler_count", handler_count, 8 if extended else 4),
        ("guard_cf_function_table", guard_table, 8 if extended else 4),
        ("guard_cf_function_count", guard_count, 8 if extended else 4),
        ("guard_flags", guard_flags, 4),
    ):
        if position + width <= len(data):
            value = int.from_bytes(data[position : position + width], "little")
            result[key] = (
                hex(value) if width == (8 if extended else 4) and key != "guard_flags" else value
            )
    return result


class Upstream68Provider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return tuple(
            CapabilityDescriptor(
                operation=operation,
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=(
                    "Static bounds-checked reader; malformed tables are reported as limitations.",
                ),
            )
            for operation in _OPERATIONS
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        path = Path(target.path)
        if path.suffix.lower() in (".dol", ".dtb", ".ips", ".pb", ".bin"):
            return TargetSupport("supported")
        if target.format in ("pe", "elf", "mach-o", "unknown", "file"):
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported", reason="not a supported static target", code="target_format_unsupported"
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del profile
        try:
            data = Path(target.path).read_bytes()
        except OSError as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        if operation == "inspect_pe_native_metadata":
            info = parse_pe(data)
            if info is None:
                return err(AnalysisInputError(operation=operation, message="not a PE file"))
            imports, limitations = _pe_imports(data, info)
            return ok(
                AnalysisExecution(
                    result={
                        "imports": imports,
                        "delay_imports": _pe_delay(data, info),
                        "tls": _pe_tls(data, info),
                        "load_config": _pe_load_config(data, info),
                        "import_count": sum(len(item["functions"]) for item in imports),
                    },
                    provider=self.identity(),
                    limitations=tuple(limitations),
                )
            )
        if operation == "inspect_dol_executable":
            if len(data) < 0x100:
                return err(
                    AnalysisInputError(operation=operation, message="DOL header is truncated")
                )
            text_offsets = struct.unpack_from(">7I", data, 0x00)
            data_offsets = struct.unpack_from(">11I", data, 0x1C)
            text_addresses = struct.unpack_from(">7I", data, 0x48)
            data_addresses = struct.unpack_from(">11I", data, 0x64)
            entry = struct.unpack_from(">I", data, 0xE0)[0]
            sections = []
            for index in range(7):
                if text_offsets[index] and text_addresses[index]:
                    sections.append(
                        {
                            "kind": "text",
                            "index": index,
                            "offset": text_offsets[index],
                            "address": hex(text_addresses[index]),
                        }
                    )
            for index in range(11):
                if data_offsets[index] and data_addresses[index]:
                    sections.append(
                        {
                            "kind": "data",
                            "index": index,
                            "offset": data_offsets[index],
                            "address": hex(data_addresses[index]),
                        }
                    )
            return ok(
                AnalysisExecution(
                    result={
                        "format": "dol",
                        "architecture": "powerpc",
                        "entry": hex(entry),
                        "sections": sections,
                        "section_count": len(sections),
                    },
                    provider=self.identity(),
                )
            )
        if operation == "inspect_flattened_devicetree":
            if len(data) < 40 or data[:4] != b"\xd0\x0d\xfe\xed":
                return err(
                    AnalysisInputError(operation=operation, message="not a flattened device tree")
                )
            (
                _magic,
                total,
                off_struct,
                off_strings,
                _off_mem,
                _version,
                _last,
                _cpu,
                size_strings,
                size_struct,
            ) = struct.unpack_from(">10I", data, 0)
            if total > len(data) or off_struct + size_struct > len(data):
                return err(
                    AnalysisInputError(
                        operation=operation, message="FDT offsets are outside the file"
                    )
                )
            strings = data[off_strings : off_strings + size_strings]
            cursor = off_struct
            end = off_struct + size_struct
            stack: list[str] = []
            nodes: list[dict[str, Any]] = []
            while cursor + 4 <= end:
                token = struct.unpack_from(">I", data, cursor)[0]
                cursor += 4
                if token == 1:
                    stop = data.find(b"\0", cursor, end)
                    if stop < 0:
                        break
                    name = data[cursor:stop].decode("utf-8", errors="replace")
                    cursor = stop + 1
                    stack.append(name)
                    nodes.append({"path": "/" + "/".join(stack), "name": name, "properties": {}})
                elif token == 2:
                    if stack:
                        stack.pop()
                elif token == 3:
                    if cursor + 8 > end:
                        break
                    length, name_offset = struct.unpack_from(">II", data, cursor)
                    cursor += 8
                    key = strings[name_offset:].split(b"\0", 1)[0].decode("utf-8", errors="replace")
                    value = data[cursor : cursor + length]
                    cursor += length
                    if nodes:
                        nodes[-1]["properties"][key] = (
                            value.decode("utf-8", errors="replace").rstrip("\0")
                            if all(31 < byte < 127 or byte == 0 for byte in value)
                            else value.hex()[:2000]
                        )
                elif token == 4:
                    continue
                elif token == 9:
                    break
            mmio = []
            for node in nodes:
                props = node["properties"]
                if "reg" in props and any(
                    key in props for key in ("compatible", "device_type", "mmio")
                ):
                    reg_text = str(props["reg"])
                    ranges = []
                    for index in range(0, len(reg_text), 16):
                        chunk = reg_text[index : index + 16]
                        if len(chunk) == 16:
                            start = int(chunk[:8], 16)
                            size = int(chunk[8:], 16)
                            ranges.append({"start": start, "size": size, "end": start + size})
                    mmio.append({"path": node["path"], "reg": reg_text[:200], "ranges": ranges})
            attributed = []
            disassembly = parameters.get("disassembly")
            if isinstance(disassembly, str) and mmio:
                try:
                    text = Path(disassembly).read_text(encoding="utf-8", errors="replace")
                except OSError:
                    text = ""
                addresses = {int(item, 16) for item in re.findall(r"0x[0-9a-fA-F]+", text)}
                for candidate in mmio:
                    for region in candidate["ranges"]:
                        hits = [
                            hex(address)
                            for address in addresses
                            if region["start"] <= address < region["end"]
                        ]
                        if hits:
                            attributed.append(
                                {
                                    "path": candidate["path"],
                                    "start": hex(region["start"]),
                                    "addresses": sorted(set(hits))[:100],
                                }
                            )
            return ok(
                AnalysisExecution(
                    result={
                        "format": "fdt",
                        "total_size": total,
                        "node_count": len(nodes),
                        "nodes": nodes[:500],
                        "mmio_candidates": mmio[:200],
                        "mmio_attributed": attributed,
                    },
                    provider=self.identity(),
                )
            )
        if operation == "inspect_protobuf_body":
            raw = data
            grpc = None
            if len(raw) >= 5 and raw[0] in (0, 1):
                length = int.from_bytes(raw[1:5], "big")
                if 5 + length <= len(raw):
                    grpc = {"compressed": raw[0] == 1, "message_length": length}
                    raw = raw[5 : 5 + length]
            message = _protobuf(raw)
            return ok(
                AnalysisExecution(
                    result={
                        "format": "protobuf",
                        "grpc": grpc,
                        "fields": message["fields"],
                        "truncated": message["truncated"],
                    },
                    provider=self.identity(),
                    limitations=("Schema-less wire decoding; field names are unavailable.",),
                )
            )
        if operation == "inspect_packaged_application":
            pyinstaller = _pyinstaller_archive(data)
            sea = _node_sea_blob(data)
            ips = None
            if data.lstrip().startswith(b"{"):
                try:
                    document = json.loads(data.decode("utf-8", errors="replace"))
                    if isinstance(document, dict):
                        ips = {
                            "bug_type": document.get("bug_type"),
                            "name": document.get("name") or document.get("process"),
                            "exception": document.get("exception"),
                        }
                except ValueError:
                    pass
            return ok(
                AnalysisExecution(
                    result={
                        "format": "packaged",
                        "pyinstaller": pyinstaller,
                        "node_sea": sea,
                        "ips": ips,
                    },
                    provider=self.identity(),
                )
            )
        return err(
            AnalysisInputError(operation=operation, message=f"unsupported operation {operation}")
        )


def _node_sea_blob(data: bytes) -> dict[str, Any] | None:
    name = b"NODE_SEA_BLOB"
    offset = data.find(name)
    if offset < 0:
        return None
    result: dict[str, Any] = {"marker_offset": offset}
    header_offset = offset - 12
    if header_offset >= 0:
        try:
            namesz, descsz, _kind = struct.unpack_from("<III", data, header_offset)
        except struct.error:
            return result
        aligned = (namesz + 3) & ~3
        start = offset + aligned
        if namesz >= len(name) and descsz and start + descsz <= len(data):
            blob = data[start : start + descsz]
            result.update(
                {
                    "blob_offset": start,
                    "blob_size": descsz,
                    "sha256": hashlib.sha256(blob).hexdigest(),
                    "header_hex": blob[:32].hex(),
                }
            )
    return result


def _pyinstaller_archive(data: bytes) -> dict[str, Any] | None:
    magic = b"MEI\014\013\012\013\016"
    cookie_offset = data.rfind(magic, max(0, len(data) - 65536))
    if cookie_offset < 0:
        return None
    cookie = data[cookie_offset : cookie_offset + 88]
    if len(cookie) < 88:
        return {"cookie_offset": cookie_offset, "entries": [], "truncated": True}
    try:
        _magic, package_length, toc_offset, toc_length, py_version, pylibname = struct.unpack(
            ">8sIIII64s", cookie
        )
    except struct.error:
        return {"cookie_offset": cookie_offset, "entries": [], "truncated": True}
    starts = [len(data) - package_length, cookie_offset - package_length]
    fallback: dict[str, Any] | None = None
    for start in starts:
        if start < 0 or start + toc_offset + toc_length > len(data):
            continue
        entries: list[dict[str, Any]] = []
        cursor = start + toc_offset
        end = cursor + toc_length
        while cursor + 18 <= end and len(entries) < 2000:
            entry_length = struct.unpack_from(">I", data, cursor)[0]
            if entry_length < 18 or cursor + entry_length > end:
                break
            offset, compressed, uncompressed, flag, typecode = struct.unpack_from(
                ">IIIBc", data, cursor + 4
            )
            name = (
                data[cursor + 18 : cursor + entry_length]
                .split(b"\0", 1)[0]
                .decode("utf-8", errors="replace")
            )
            entries.append(
                {
                    "name": name,
                    "type": typecode.decode("ascii", errors="replace"),
                    "offset": offset,
                    "compressed": compressed,
                    "uncompressed": uncompressed,
                    "compressed_flag": bool(flag),
                }
            )
            cursor += entry_length
        if entries:
            return {
                "cookie_offset": cookie_offset,
                "package_length": package_length,
                "toc_offset": toc_offset,
                "toc_length": toc_length,
                "py_version": py_version,
                "pylibname": pylibname.split(b"\0", 1)[0].decode("utf-8", errors="replace"),
                "entries": entries,
            }
        if fallback is None:
            fallback = {
                "cookie_offset": cookie_offset,
                "package_length": package_length,
                "toc_offset": toc_offset,
                "toc_length": toc_length,
                "py_version": py_version,
                "pylibname": pylibname.split(b"\0", 1)[0].decode("utf-8", errors="replace"),
                "entries": [],
            }
    return fallback or {"cookie_offset": cookie_offset, "entries": [], "truncated": True}


def _protobuf(data: bytes, depth: int = 0) -> dict[str, Any]:
    fields: list[dict[str, Any]] = []
    cursor = 0
    truncated = False
    while cursor < len(data) and len(fields) < _MAX_ITEMS:
        key = 0
        shift = 0
        while cursor < len(data):
            byte = data[cursor]
            cursor += 1
            key |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                break
        if cursor > len(data) or shift > 63:
            truncated = True
            break
        number, wire = key >> 3, key & 7
        if number <= 0:
            truncated = True
            break
        if wire == 0:
            value = 0
            shift = 0
            while cursor < len(data):
                byte = data[cursor]
                cursor += 1
                value |= (byte & 0x7F) << shift
                shift += 7
                if not byte & 0x80:
                    break
            fields.append({"field": number, "wire": "varint", "value": value})
        elif wire == 1:
            if cursor + 8 > len(data):
                truncated = True
                break
            fields.append(
                {"field": number, "wire": "fixed64", "value": data[cursor : cursor + 8].hex()}
            )
            cursor += 8
        elif wire == 2:
            length = 0
            shift = 0
            while cursor < len(data):
                byte = data[cursor]
                cursor += 1
                length |= (byte & 0x7F) << shift
                shift += 7
                if not byte & 0x80:
                    break
            if cursor + length > len(data):
                truncated = True
                break
            payload = data[cursor : cursor + length]
            cursor += length
            item: dict[str, Any] = {"field": number, "wire": "bytes", "length": length}
            if all(31 < byte < 127 or byte in (9, 10, 13) for byte in payload):
                item["text"] = payload.decode("utf-8", errors="replace")[:2000]
            elif depth < 4:
                nested = _protobuf(payload, depth + 1)
                if nested["fields"]:
                    item["message"] = nested["fields"]
                    item["truncated"] = nested["truncated"]
                else:
                    item["hex"] = payload.hex()[:2000]
            else:
                item["hex"] = payload.hex()[:2000]
            fields.append(item)
        elif wire == 5:
            if cursor + 4 > len(data):
                truncated = True
                break
            fields.append(
                {"field": number, "wire": "fixed32", "value": data[cursor : cursor + 4].hex()}
            )
            cursor += 4
        else:
            truncated = True
            break
    return {"fields": fields, "truncated": truncated}


__all__ = ["Upstream68Provider"]
