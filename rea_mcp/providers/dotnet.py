"""Built-in .NET managed assembly provider (static PE/CLI metadata).

Reads PE/CLI metadata without loading or executing the assembly: runtime version,
metadata streams, and table row counts (types, methods, fields, assembly refs).
"""

from __future__ import annotations

import mmap
import struct
from pathlib import Path
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .formats.cil import CilError, disassemble, parse_method_body
from .formats.cli_metadata import load_metadata, parse_managed_members, resolve_token
from .formats.pe import PeInfo, parse_pe
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="dotnet", name="REA-Python managed (.NET) metadata", version="1")

_METADATA_SIGNATURE = b"BSJB"
_TABLE_NAMES: dict[int, str] = {
    0x00: "Module",
    0x01: "TypeRef",
    0x02: "TypeDef",
    0x04: "Field",
    0x06: "MethodDef",
    0x08: "Param",
    0x20: "Assembly",
    0x23: "AssemblyRef",
    0x26: "ManifestResource",
}


class ManagedStaticProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="inspect_managed_artifact",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=("Static metadata only; IL/method bodies are not decoded.",),
            ),
            CapabilityDescriptor(
                operation="inspect_managed_members",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=("Member names and counts; IL bodies are not decoded.",),
            ),
            CapabilityDescriptor(
                operation="disassemble_managed_method",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=("IL opcodes only; tokens are not resolved to member names.",),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format != "pe":
            return TargetSupport(
                "unsupported",
                reason="managed metadata requires a PE image",
                code="target_format_unsupported",
            )
        return TargetSupport("supported")

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del profile
        if operation not in (
            "inspect_managed_artifact",
            "inspect_managed_members",
            "disassemble_managed_method",
        ):
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        try:
            data = Path(target.path).read_bytes()
        except OSError as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))

        pe = parse_pe(data)
        if pe is None:
            return err(AnalysisInputError(operation=operation, message="Not a PE image"))
        if not pe.has_clr:
            return ok(
                AnalysisExecution(
                    result={"is_managed": False, "runtime_version": None, "tables": {}},
                    provider=_PROVIDER,
                    limitations=("No CLR runtime header is present; the image is not managed.",),
                )
            )

        metadata_offset = _rva_to_offset(pe, pe.clr_header_rva)
        if metadata_offset is None or metadata_offset + 16 > len(data):
            return err(
                AnalysisInputError(operation=operation, message="CLI header is outside the image")
            )
        meta_rva, _meta_size = struct.unpack_from("<II", data, metadata_offset + 8)
        metadata_root = _rva_to_offset(pe, meta_rva)
        if metadata_root is None:
            return err(
                AnalysisInputError(operation=operation, message="CLI metadata is outside the image")
            )

        parsed = _parse_metadata_root(data, metadata_root)
        if parsed is None:
            return err(
                AnalysisInputError(operation=operation, message="CLI metadata root is malformed")
            )
        runtime_version, streams = parsed

        if operation == "inspect_managed_members":
            members = parse_managed_members(data, streams)
            if members is None:
                return err(
                    AnalysisInputError(
                        operation=operation, message="CLI metadata tables could not be decoded"
                    )
                )
            members["runtime_version"] = runtime_version
            return ok(
                AnalysisExecution(
                    result=members,
                    provider=_PROVIDER,
                    limitations=("Member names and counts only; IL bodies are not decoded.",),
                )
            )

        if operation == "disassemble_managed_method":
            return _disassemble_method(pe, data, streams, operation, parameters)

        tables = _parse_tables(data, metadata_root, streams)

        return ok(
            AnalysisExecution(
                result={
                    "is_managed": True,
                    "runtime_version": runtime_version,
                    "streams": sorted(streams.keys()),
                    "tables": {
                        _TABLE_NAMES.get(index, f"Table{index:#x}"): table["rows"]
                        for index, table in tables.items()
                        if index in _TABLE_NAMES
                    },
                },
                provider=_PROVIDER,
                limitations=("Member lists and IL bodies are not decoded in this version.",),
            )
        )


def _disassemble_method(
    pe: PeInfo,
    data: bytes | mmap.mmap,
    streams: dict[str, int],
    operation: str,
    parameters: dict[str, Any],
) -> Result[AnalysisExecution, AnalysisError]:
    members = parse_managed_members(data, streams)
    if members is None:
        return err(
            AnalysisInputError(
                operation=operation, message="CLI metadata tables could not be decoded"
            )
        )
    wanted_type = parameters.get("type")
    wanted_method = parameters.get("method")
    if not wanted_method:
        return err(
            AnalysisInputError(
                operation=operation, message="disassemble_managed_method requires a method name"
            )
        )
    candidates: list[dict[str, Any]] = []
    for type_entry in members["types"]:
        if (
            wanted_type
            and type_entry["full_name"] != wanted_type
            and type_entry["name"] != wanted_type
        ):
            continue
        for method in type_entry["methods"]:
            if method["name"] == wanted_method:
                candidates.append({**method, "type": type_entry["full_name"]})
    if not candidates:
        return err(
            AnalysisInputError(
                operation=operation, message=f"method {wanted_method!r} was not found"
            )
        )
    chosen = candidates[0]
    offset = _rva_to_offset(pe, chosen["rva"])
    if offset is None:
        return err(
            AnalysisInputError(operation=operation, message="method body is outside the image")
        )
    try:
        header, code = parse_method_body(bytes(data), offset)
    except CilError as cause:
        return err(AnalysisInputError(operation=operation, message=str(cause)))
    instructions = disassemble(code)
    context = load_metadata(data, streams)
    if context is not None:
        for instruction in instructions:
            operand = instruction.get("operand")
            if isinstance(operand, str) and operand.startswith("0x"):
                resolved = resolve_token(context, int(operand, 16))
                if resolved:
                    instruction["resolved"] = resolved
    return ok(
        AnalysisExecution(
            result={
                "method": chosen["name"],
                "type": chosen["type"],
                "rva": hex(chosen["rva"]),
                "header": header,
                "code_size": len(code),
                "instructions": instructions,
                "candidate_count": len(candidates),
            },
            provider=_PROVIDER,
            limitations=(
                "Tokens are resolved to member names where the metadata tables are readable.",
            ),
        )
    )


def _rva_to_offset(pe: PeInfo, rva: int) -> int | None:
    for section in pe.sections:
        span = max(section.virtual_size, section.size_of_raw_data)
        if section.virtual_address <= rva < section.virtual_address + span:
            return rva - section.virtual_address + section.pointer_to_raw_data
    return None


def _parse_metadata_root(data: bytes | mmap.mmap, root: int) -> tuple[str, dict[str, int]] | None:
    if root + 20 > len(data) or data[root : root + 4] != _METADATA_SIGNATURE:
        return None
    try:
        _major, _minor, _reserved, version_length = struct.unpack_from("<HHII", data, root + 4)
    except struct.error:
        return None
    cursor = root + 16
    if version_length == 0 or cursor + version_length > len(data):
        return None
    version_raw = data[cursor : cursor + version_length]
    runtime_version = version_raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    cursor += version_length
    # Version string is padded to a 4-byte boundary.
    cursor = (cursor + 3) & ~3
    if cursor + 4 > len(data):
        return None
    _flags, stream_count = struct.unpack_from("<HH", data, cursor)
    cursor += 4

    streams: dict[str, int] = {}
    for _ in range(stream_count):
        if cursor + 8 > len(data):
            return None
        offset, _size = struct.unpack_from("<II", data, cursor)
        cursor += 8
        name_start = cursor
        while cursor < len(data) and data[cursor] != 0x00:
            cursor += 1
        name = data[name_start:cursor].decode("utf-8", errors="replace")
        cursor = (cursor + 4) & ~3
        streams[name] = root + offset
    return runtime_version, streams


def _parse_tables(
    data: bytes | mmap.mmap, root: int, streams: dict[str, int]
) -> dict[int, dict[str, int]]:
    tables: dict[int, dict[str, int]] = {}
    if "#~" not in streams:
        return tables
    tables_base = streams["#~"]
    if tables_base + 24 > len(data):
        return tables
    try:
        valid, _sorted = struct.unpack_from("<QQ", data, tables_base + 8)
    except struct.error:
        return tables
    cursor = tables_base + 24
    for index in range(64):
        if valid & (1 << index):
            if cursor + 4 > len(data):
                break
            (rows,) = struct.unpack_from("<I", data, cursor)
            cursor += 4
            tables[index] = {"rows": rows}
    _ = root
    return tables


__all__ = ["ManagedStaticProvider"]
