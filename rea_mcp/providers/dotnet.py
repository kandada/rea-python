"""Built-in .NET managed assembly provider (static PE/CLI metadata).

Reads PE/CLI metadata without loading or executing the assembly: runtime version,
metadata streams, and table row counts (types, methods, fields, assembly refs).
"""

from __future__ import annotations

import mmap
import struct
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .formats.cil import CilError, disassemble, parse_method_body
from .formats.cli_metadata import load_metadata, resolve_token
from .formats.io import open_target
from .formats.managed_inspection import parse_managed_inspection
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
            with open_target(target.path) as data:
                return _analyze_managed(data, operation, parameters, target)
        except OSError as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))


def _paginate_types(members: dict[str, Any], parameters: dict[str, Any]) -> None:
    types = members.get("types")
    if not isinstance(types, list):
        return
    offset = max(0, int(parameters.get("offset") or 0))
    limit = min(1000, max(1, int(parameters.get("limit") or 256)))
    total = len(types)
    start = min(offset, total)
    page = types[start : start + limit]
    method_offset = max(0, int(parameters.get("method_offset") or 0))
    method_limit = min(1000, max(1, int(parameters.get("method_limit") or 64)))
    for item in page:
        methods = item.get("methods")
        if not isinstance(methods, list):
            continue
        method_total = len(methods)
        method_start = min(method_offset, method_total)
        method_page = methods[method_start : method_start + method_limit]
        item["methods_total"] = method_total
        item["methods_offset"] = method_start
        item["methods"] = method_page
        item["methods_next_offset"] = (
            method_start + len(method_page)
            if method_start + len(method_page) < method_total
            else None
        )
    members["types_total"] = total
    members["types_offset"] = start
    members["types"] = page
    members["next_offset"] = start + len(page) if start + len(page) < total else None
    page_tokens = {entry.get("token") for entry in page}
    if isinstance(members.get("fields"), list):
        members["fields"] = [
            item for item in members["fields"] if item.get("declaring_type_token") in page_tokens
        ]
    if isinstance(members.get("methods"), list):
        members["methods"] = [
            item for item in members["methods"] if item.get("declaring_type_token") in page_tokens
        ]
    if isinstance(members.get("call_edges"), list):
        members["call_edges"] = [
            item
            for item in members["call_edges"]
            if item.get("caller_token") in {method.get("token") for method in members["methods"]}
        ]
    if isinstance(members.get("field_accesses"), list):
        members["field_accesses"] = [
            item
            for item in members["field_accesses"]
            if item.get("method_token") in {method.get("token") for method in members["methods"]}
        ]
    if isinstance(members.get("field_initializers"), list):
        members["field_initializers"] = [
            item
            for item in members["field_initializers"]
            if item.get("method_token") in {method.get("token") for method in members["methods"]}
        ]


def _analyze_managed(
    data: bytes | mmap.mmap,
    operation: str,
    parameters: dict[str, Any],
    target: BinaryTarget,
) -> Result[AnalysisExecution, AnalysisError]:
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
    runtime_version, streams, stream_sizes = parsed

    if operation == "inspect_managed_members":
        try:
            members = parse_managed_inspection(
                bytes(data),
                streams,
                stream_sizes=stream_sizes,
                runtime_version=runtime_version,
                rva_to_offset=lambda rva: _rva_to_offset(pe, rva),
                type_names=parameters.get("type_names"),
                detail=str(parameters.get("detail") or "complete"),
                include_fields=bool(parameters.get("include_fields", True)),
                include_methods=bool(parameters.get("include_methods", True)),
                include_constants=bool(parameters.get("include_constants", True)),
                include_member_refs=bool(parameters.get("include_member_refs", True)),
                include_exported_types=bool(parameters.get("include_exported_types", True)),
                include_user_strings=bool(parameters.get("include_user_strings", True)),
                include_bodies=parameters.get("include_bodies"),
                include_edges=bool(parameters.get("include_edges", True)),
            )
        except Exception as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        members["runtime_version"] = runtime_version
        members["artifact"] = {
            "path": target.path,
            "sha256": target.sha256,
            "byte_length": len(data),
            "format": "pe",
        }
        members["identity_scope"]["requires_artifact_sha256"] = target.sha256
        _paginate_types(members, parameters)
        return ok(
            AnalysisExecution(
                result=members,
                provider=_PROVIDER,
                limitations=tuple(members.get("limitations") or ()),
            )
        )

    if operation == "disassemble_managed_method":
        return _disassemble_method(pe, data, streams, stream_sizes, operation, parameters)

    tables = _parse_tables(data, metadata_root, streams, stream_sizes)
    try:
        summary = parse_managed_inspection(
            bytes(data),
            streams,
            stream_sizes=stream_sizes,
            runtime_version=runtime_version,
            rva_to_offset=lambda rva: _rva_to_offset(pe, rva),
            detail="summary",
            include_fields=False,
            include_methods=False,
            include_constants=False,
            include_member_refs=False,
            include_exported_types=True,
            include_user_strings=False,
            include_bodies=False,
            include_edges=False,
        )
    except Exception as cause:
        return err(AnalysisInputError(operation=operation, message=str(cause)))
    summary["artifact"] = {
        "path": target.path,
        "sha256": target.sha256,
        "byte_length": len(data),
        "format": "pe",
    }
    summary["identity_scope"]["requires_artifact_sha256"] = target.sha256
    summary["is_managed"] = True
    summary["runtime_version"] = runtime_version
    summary["streams"] = sorted(streams.keys())
    summary["tables"] = {
        _TABLE_NAMES.get(index, f"Table{index:#x}"): table["rows"]
        for index, table in tables.items()
        if index in _TABLE_NAMES
    }
    return ok(
        AnalysisExecution(
            result=summary,
            provider=_PROVIDER,
            limitations=tuple(summary.get("limitations") or ()),
        )
    )


def _disassemble_method(
    pe: PeInfo,
    data: bytes | mmap.mmap,
    streams: dict[str, int],
    stream_sizes: dict[str, int],
    operation: str,
    parameters: dict[str, Any],
) -> Result[AnalysisExecution, AnalysisError]:
    try:
        inspection = parse_managed_inspection(
            bytes(data),
            streams,
            stream_sizes=stream_sizes,
            rva_to_offset=lambda rva: _rva_to_offset(pe, rva),
            include_fields=False,
            include_methods=True,
            include_constants=False,
            include_member_refs=False,
            include_exported_types=False,
            include_user_strings=False,
            include_bodies=False,
            include_edges=False,
        )
    except Exception as cause:
        return err(AnalysisInputError(operation=operation, message=str(cause)))
    wanted_type = parameters.get("type")
    wanted_method = parameters.get("method")
    wanted_token = parameters.get("token")
    wanted_rva = parameters.get("rva")
    wanted_signature = parameters.get("signature")
    if not wanted_method and not wanted_token and not wanted_rva:
        return err(
            AnalysisInputError(
                operation=operation,
                message="disassemble_managed_method requires a method name, token or rva",
            )
        )
    candidates: list[dict[str, Any]] = []
    for method in inspection.get("methods", []):
        if (
            wanted_type
            and method.get("declaring_type") != wanted_type
            and str(method.get("declaring_type") or "").split("+")[-1].split(".")[-1] != wanted_type
        ):
            continue
        if wanted_method and method.get("name") != wanted_method:
            continue
        if wanted_token and str(method.get("token", "")).lower() != str(wanted_token).lower():
            continue
        if wanted_rva is not None:
            try:
                rva_value = int(str(wanted_rva), 0)
            except ValueError:
                return err(
                    AnalysisInputError(operation=operation, message=f"invalid rva: {wanted_rva}")
                )
            if int(method.get("rva", 0)) != rva_value:
                continue
        if wanted_signature:
            raw = str((method.get("signature") or {}).get("raw_sha256") or "")
            if not raw.startswith(str(wanted_signature).lower()):
                continue
        candidates.append(method)
    if not candidates:
        return err(
            AnalysisInputError(
                operation=operation,
                message=f"method {wanted_method or wanted_token or wanted_rva!r} was not found",
            )
        )
    if len(candidates) > 1 and not (wanted_token or wanted_rva or wanted_signature):
        return err(
            AnalysisInputError(
                operation=operation,
                message=(
                    f"{len(candidates)} methods match; provide token, rva or signature. "
                    "Candidates: "
                    + ", ".join(
                        f"{item.get('declaring_type')}::{item.get('name')} {item.get('token')} rva={item.get('rva')}"
                        for item in candidates[:20]
                    )
                ),
            )
        )
    chosen = candidates[0]
    offset = _rva_to_offset(pe, int(chosen["rva"]))
    if offset is None:
        return err(
            AnalysisInputError(operation=operation, message="method body is outside the image")
        )
    try:
        header, code = parse_method_body(data, offset)
    except CilError as cause:
        return err(AnalysisInputError(operation=operation, message=str(cause)))
    instructions = disassemble(code)
    context = load_metadata(data, streams, stream_sizes)
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
                "type": chosen["declaring_type"],
                "token": chosen.get("token"),
                "signature": chosen.get("signature"),
                "rva": hex(int(chosen["rva"])),
                "header": header,
                "code_size": len(code),
                "instructions": instructions,
                "candidate_count": len(candidates),
                "chosen_candidate_index": 0,
                "candidates": candidates[:20] if len(candidates) > 1 else [],
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


def _parse_metadata_root(
    data: bytes | mmap.mmap, root: int
) -> tuple[str, dict[str, int], dict[str, int]] | None:
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
    stream_sizes: dict[str, int] = {}
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
        stream_sizes[name] = _size
    return runtime_version, streams, stream_sizes


def _parse_tables(
    data: bytes | mmap.mmap,
    root: int,
    streams: dict[str, int],
    stream_sizes: dict[str, int] | None = None,
) -> dict[int, dict[str, int]]:
    del stream_sizes
    tables: dict[int, dict[str, int]] = {}
    if "#~" not in streams and "#-" not in streams:
        return tables
    tables_base = streams.get("#~", streams.get("#-", 0))
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


def _metadata_streams(data: Any, pe: Any) -> Any:
    import struct as _struct

    metadata_offset = _rva_to_offset(pe, pe.clr_header_rva)
    if metadata_offset is None or metadata_offset + 16 > len(data):
        return None
    meta_rva, _meta_size = _struct.unpack_from("<II", data, metadata_offset + 8)
    metadata_root = _rva_to_offset(pe, meta_rva)
    if metadata_root is None:
        return None
    return _parse_metadata_root(data, metadata_root)


def _member_sets(path: str) -> Result[dict[str, set[str]], AnalysisError]:
    from pathlib import Path as _Path

    try:
        data = _Path(path).read_bytes()
    except OSError as cause:
        return err(AnalysisInputError(operation="compare_managed_members", message=str(cause)))
    pe = parse_pe(data)
    if pe is None or not pe.has_clr:
        return ok({"types": set(), "fields": set(), "methods": set(), "nested": set()})
    parsed = _metadata_streams(data, pe)
    if parsed is None:
        return ok({"types": set(), "fields": set(), "methods": set(), "nested": set()})
    _runtime, streams, stream_sizes = parsed
    try:
        inspection = parse_managed_inspection(
            data,
            streams,
            stream_sizes=stream_sizes,
            detail="complete",
            include_fields=True,
            include_methods=True,
            include_constants=True,
            include_member_refs=False,
            include_exported_types=False,
            include_user_strings=False,
            include_bodies=False,
            include_edges=False,
        )
    except Exception as cause:
        return err(AnalysisInputError(operation="compare_managed_members", message=str(cause)))
    types = {str(item.get("full_name")) for item in inspection.get("types", [])}
    fields = {
        f"{item.get('declaring_type')}::{item.get('name')}::{(item.get('signature') or {}).get('raw_sha256')}::{item.get('constant_type')}:{item.get('constant')!r}"
        for item in inspection.get("fields", [])
    }
    methods = {
        f"{item.get('declaring_type')}::{item.get('name')}::{(item.get('signature') or {}).get('raw_sha256')}"
        for item in inspection.get("methods", [])
    }
    nested = {
        f"{item.get('full_name')}::{item.get('enclosing_type_token')}"
        for item in inspection.get("types", [])
        if item.get("enclosing_type_token")
    }
    legacy_methods = {
        f"{item.get('declaring_type')}::{item.get('name')}"
        for item in inspection.get("methods", [])
    }
    return ok(
        {
            "types": types,
            "fields": fields,
            "methods": methods,
            "nested": nested,
            "legacy_methods": legacy_methods,
        }
    )


def _diff(left: set[str], right: set[str]) -> dict[str, Any]:
    added = sorted(right - left)
    removed = sorted(left - right)
    return {
        "added_count": len(added),
        "removed_count": len(removed),
        "added": added[:500],
        "removed": removed[:500],
        "truncated": len(added) > 500 or len(removed) > 500,
    }


def compare_managed_members(
    left_path: str, right_path: str
) -> Result[dict[str, Any], AnalysisError]:
    """Compare managed types, fields, methods and nesting by exact identity."""

    left = _member_sets(left_path)
    if not left.ok:
        return err(left.error)
    right = _member_sets(right_path)
    if not right.ok:
        return err(right.error)
    legacy_left = left.value.get("legacy_methods", set())
    legacy_right = right.value.get("legacy_methods", set())
    legacy_added = sorted(legacy_right - legacy_left)
    legacy_removed = sorted(legacy_left - legacy_right)
    categories = {
        category: _diff(left.value.get(category, set()), right.value.get(category, set()))
        for category in ("types", "fields", "methods", "nested")
    }
    changed = any(
        category["added_count"] or category["removed_count"] for category in categories.values()
    )
    return ok(
        {
            "status": "changed" if changed else "unchanged",
            "added_count": len(legacy_added),
            "removed_count": len(legacy_removed),
            "added": legacy_added[:500],
            "removed": legacy_removed[:500],
            "types": categories["types"],
            "fields": categories["fields"],
            "methods": categories["methods"],
            "nested": categories["nested"],
            "truncated": any(item["truncated"] for item in categories.values()),
            "limitations": [
                "Names alone are not a match; fields include signature hash and literal constant, methods include signature hash.",
                "Method bodies and user strings are not compared.",
            ],
        }
    )
