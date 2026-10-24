"""IL2CPP global-metadata table inspection (versions 24/27/29/31/39)."""

from __future__ import annotations

import base64
import hashlib
import struct
from pathlib import Path
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="il2cpp-metadata", name="REA-Python IL2CPP metadata", version="1")
_MAGIC = b"\xaf\x1b\xb1\xfa"
_SUPPORTED = (24, 27, 29, 31, 39)
_MAX_ROWS = 200_000
_MAX_TEXT = 4096

_SECTIONS = [
    "stringLiterals",
    "stringLiteralData",
    "strings",
    "events",
    "properties",
    "methods",
    "parameterDefaultValues",
    "fieldDefaultValues",
    "fieldAndParameterDefaultValueData",
    "fieldMarshaledSizes",
    "parameters",
    "fields",
    "genericParameters",
    "genericParameterConstraints",
    "genericContainers",
    "nestedTypes",
    "interfaces",
    "vtableMethods",
    "interfaceOffsets",
    "typeDefinitions",
    "images",
    "assemblies",
    "fieldRefs",
    "referencedAssemblies",
    "attributeData",
    "attributeDataRanges",
    "unresolvedIndirectCallParameterTypes",
    "unresolvedIndirectCallParameterRanges",
    "windowsRuntimeTypeNames",
    "windowsRuntimeStrings",
    "exportedTypeDefinitions",
]
_V27 = [
    *_SECTIONS[:24],
    "attributesInfo",
    "attributeTypes",
    "unresolvedVirtualCallParameterTypes",
    "unresolvedVirtualCallParameterRanges",
    *_SECTIONS[28:],
]
_V24 = [
    *_SECTIONS[:22],
    "metadataUsageLists",
    "metadataUsagePairs",
    "fieldRefs",
    "referencedAssemblies",
    "attributesInfo",
    "attributeTypes",
    "unresolvedVirtualCallParameterTypes",
    "unresolvedVirtualCallParameterRanges",
    "windowsRuntimeTypeNames",
    "exportedTypeDefinitions",
]
_LAYOUT = {
    24: (False, 5, False),
    27: (False, 4, False),
    29: (False, 4, False),
    31: (False, 4, True),
    39: (True, 3, True),
}


class Il2CppMetadataProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="inspect_il2cpp_metadata",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=(
                    "Static metadata rows only; native binary linkage and runtime behavior are not decoded.",
                ),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        name = Path(target.path).name.lower()
        if name == "global-metadata.dat" or name.endswith(".dat"):
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported", reason="not global-metadata.dat", code="target_format_unsupported"
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: Any,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del profile
        if operation != "inspect_il2cpp_metadata":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        try:
            data = Path(target.path).read_bytes()
        except OSError as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        try:
            result = _inspect(data)
            binary_path = parameters.get("binary_path")
            if binary_path:
                result["binary"] = _binary_link(str(binary_path), target.path, result)
        except (ValueError, struct.error, OSError) as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        return ok(AnalysisExecution(result=result, provider=_PROVIDER))


def _inspect(data: bytes) -> dict[str, Any]:
    if len(data) < 8 or data[:4] != _MAGIC:
        raise ValueError("Not a global-metadata.dat")
    version = int.from_bytes(data[4:8], "little", signed=True)
    if version not in _SUPPORTED:
        raise ValueError(f"unsupported IL2CPP metadata version {version}")
    counted, type_indices, return_token = _LAYOUT[version]
    names = _V24 if version == 24 else _V27 if version == 27 else _SECTIONS
    entry = 12 if counted else 8
    header = 8 + len(names) * entry
    if len(data) < header:
        raise ValueError("truncated IL2CPP metadata header")
    sections: dict[str, dict[str, int | None]] = {}
    for index, name in enumerate(names):
        at = 8 + index * entry
        offset, size = struct.unpack_from("<ii", data, at)
        count = struct.unpack_from("<i", data, at + 8)[0] if counted else None
        if offset < 0 or size < 0 or offset + size > len(data) or (count is not None and count < 0):
            raise ValueError(f"section {name} is outside the file")
        sections[name] = {"offset": offset, "size": size, "count": count}
    if sections[names[0]]["offset"] != header:
        raise ValueError("first metadata section does not start at the header end")
    widths = _widths(sections, counted, version)
    strings = sections["strings"]
    type_section = sections["typeDefinitions"]
    method_section = sections["methods"]
    type_count = _count(type_section, _type_record(type_indices, widths), counted)
    method_count = _count(
        method_section, _method_record(type_indices, widths, return_token), counted
    )
    types = _types(data, sections, widths, type_indices, type_count, method_count, strings)
    methods = _methods(
        data, sections, widths, type_indices, return_token, method_count, type_count, strings
    )
    images = _images(data, sections, widths, type_count, strings)
    fields = _named(data, sections, "fields", 8 + widths["type"], widths, type_count, strings)
    parameters = _named(
        data, sections, "parameters", 8 + widths["type"], widths, method_count, strings, method=True
    )
    properties = _named(data, sections, "properties", 20, widths, type_count, strings)
    events = _named(data, sections, "events", 20 + widths["type"], widths, type_count, strings)
    literals = _literals(data, sections, counted)
    return {
        "format": "il2cpp-metadata",
        "metadata_version": version,
        "byte_length": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "index_widths": widths,
        "sections": [{"name": name, **sections[name]} for name in names],
        "counts": {
            "types": len(types),
            "methods": len(methods),
            "images": len(images),
            "fields": len(fields),
            "parameters": len(parameters),
            "properties": len(properties),
            "events": len(events),
            "string_literals": len(literals),
        },
        "types": types,
        "methods": methods,
        "images": images,
        "fields": fields,
        "parameters": parameters,
        "properties": properties,
        "events": events,
        "string_literals": literals,
        "coverage": {"state": "complete", "issues": []},
        "limitations": (
            "Static metadata rows only; native method addresses and runtime behavior are not linked.",
        ),
    }


def _binary_link(path: str, metadata_path: str, metadata: dict[str, Any]) -> dict[str, Any]:
    from ..domain.binary_target import parse_binary_target
    from .native_exports import NativeExportsProvider

    parsed = parse_binary_target(path)
    if not parsed.ok:
        return {"path": path, "error": parsed.error.message, "symbols": []}
    result = NativeExportsProvider().analyze("inspect_native_exports", parsed.value, {}, None)
    if not result.ok:
        return {"path": path, "error": result.error.message, "symbols": []}
    symbols = [
        item
        for item in result.value.result.get("exports") or []
        if "il2cpp" in str(item.get("name") or "").lower()
    ]
    dumped = _run_il2cpp_dumper(path, metadata_path)
    return {
        "path": path,
        "format": result.value.result.get("format"),
        "export_count": result.value.result.get("export_count"),
        "symbols": symbols[:500],
        "symbol_count": len(symbols),
        **dumped,
    }


def _run_il2cpp_dumper(binary_path: str, metadata_path: str) -> dict[str, Any]:
    import os
    import subprocess
    import sys
    import tempfile

    root = os.environ.get("REA_IL2CPP_DUMPER")
    if not root:
        candidate = Path(__file__).resolve().parents[3] / "vendor" / "tools" / "Il2CppDumper-Python"
        if (candidate / "il2cpp_dumper_py").is_dir():
            root = str(candidate)
    if not root:
        return {
            "method_addresses_linked": False,
            "method_addresses": [],
            "limitations": [
                "Set REA_IL2CPP_DUMPER to Il2CppDumper-Python to resolve CodeRegistration method RVAs."
            ],
        }
    with tempfile.TemporaryDirectory(prefix="rea-il2cpp-link-") as output:
        env = {**os.environ, "PYTHONPATH": root}
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "il2cpp_dumper_py", binary_path, metadata_path, output],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as cause:
            return {
                "method_addresses_linked": False,
                "method_addresses": [],
                "limitations": [f"IL2CPP dumper failed: {cause}"],
            }
        script_path = Path(output) / "script.json"
        if proc.returncode != 0 or not script_path.is_file():
            tail = (proc.stderr or proc.stdout or "").strip()[-500:]
            return {
                "method_addresses_linked": False,
                "method_addresses": [],
                "limitations": [
                    f"IL2CPP dumper did not produce script.json (exit {proc.returncode}): {tail}"
                ],
            }
        try:
            import json

            payload = json.loads(script_path.read_text(encoding="utf-8"))
            methods = payload.get("ScriptMethod") or []
        except (OSError, ValueError) as cause:
            return {
                "method_addresses_linked": False,
                "method_addresses": [],
                "limitations": [f"IL2CPP dumper script.json is unreadable: {cause}"],
            }
    rows = [
        {
            "rva": f"0x{int(item.get('Address') or 0):x}",
            "name": item.get("Name"),
            "signature": item.get("Signature"),
        }
        for item in methods
        if isinstance(item, dict)
    ]
    return {
        "method_addresses_linked": bool(rows),
        "method_addresses": rows[:100000],
        "method_address_count": len(rows),
        "dumper": "Il2CppDumper-Python",
        "limitations": (
            [] if rows else ["IL2CPP dumper produced no non-abstract method addresses."]
        ),
    }


def _widths(
    sections: dict[str, dict[str, int | None]], counted: bool, version: int
) -> dict[str, int]:
    if not counted:
        return {"type_definition": 4, "generic_container": 4, "parameter": 4, "type": 4}

    def width(name: str) -> int:
        count = int(sections[name]["count"] or 0)
        return 1 if count <= 0xFF else 2 if count <= 0xFFFF else 4

    return {
        "type_definition": width("typeDefinitions"),
        "generic_container": width("genericContainers"),
        "parameter": width("parameters"),
        "type": width("typeDefinitions"),
    }


def _count(section: dict[str, int | None], record: int, counted: bool) -> int:
    if counted:
        count = int(section["count"] or 0)
        if count and int(section["size"] or 0) % count:
            raise ValueError("section size is not a multiple of its count")
        return count
    size = int(section["size"] or 0)
    if size % record:
        raise ValueError("section size is not a whole record multiple")
    return size // record


def _type_record(type_indices: int, widths: dict[str, int]) -> int:
    return 68 + type_indices * widths["type"] + widths["generic_container"]


def _method_record(type_indices: int, widths: dict[str, int], return_token: bool) -> int:
    return (
        16
        + (4 if return_token else 0)
        + widths["type_definition"]
        + widths["type"]
        + widths["parameter"]
        + widths["generic_container"]
    )


def _string(data: bytes, base: int, index: int) -> str:
    if index < 0 or base + index >= len(data):
        return ""
    end = data.find(b"\x00", base + index)
    if end < 0:
        end = len(data)
    return data[base + index : end].decode("utf-8", errors="replace")[:_MAX_TEXT]


def _types(
    data: bytes,
    sections: dict[str, dict[str, int | None]],
    widths: dict[str, int],
    type_indices: int,
    count: int,
    method_total: int,
    strings: dict[str, int | None],
) -> list[dict[str, Any]]:
    section = sections["typeDefinitions"]
    record = _type_record(type_indices, widths)
    rows = []
    for index in range(min(count, _MAX_ROWS)):
        at = int(section["offset"] or 0) + index * record
        starts = at + 12 + type_indices * widths["type"] + widths["generic_container"]
        counts_at = starts + 32
        row = {
            "name": _string(
                data, int(strings["offset"] or 0), struct.unpack_from("<i", data, at)[0]
            ),
            "namespace": _string(
                data, int(strings["offset"] or 0), struct.unpack_from("<i", data, at + 4)[0]
            ),
            "method_start": struct.unpack_from("<i", data, starts + 4)[0],
            "method_count": struct.unpack_from("<H", data, counts_at)[0],
            "nested_type_start": struct.unpack_from("<i", data, starts + 16)[0],
            "nested_type_count": struct.unpack_from("<H", data, counts_at + 8)[0],
            "declaring_type": -1,
        }
        if row["method_count"] and (
            row["method_start"] < 0 or row["method_start"] + row["method_count"] > method_total
        ):
            raise ValueError(f"type {index} method range is outside the methods table")
        rows.append(row)
    return rows


def _methods(
    data: bytes,
    sections: dict[str, dict[str, int | None]],
    widths: dict[str, int],
    type_indices: int,
    return_token: bool,
    count: int,
    type_total: int,
    strings: dict[str, int | None],
) -> list[dict[str, Any]]:
    section = sections["methods"]
    record = _method_record(type_indices, widths, return_token)
    rows = []
    for index in range(min(count, _MAX_ROWS)):
        at = int(section["offset"] or 0) + index * record
        declaring = _read_index(data, at + 4, widths["type_definition"])
        if declaring < -1 or declaring >= type_total:
            raise ValueError(f"method {index} declaring type is out of range")
        rows.append(
            {
                "name": _string(
                    data, int(strings["offset"] or 0), struct.unpack_from("<i", data, at)[0]
                ),
                "declaring_type": declaring,
            }
        )
    return rows


def _images(
    data: bytes,
    sections: dict[str, dict[str, int | None]],
    widths: dict[str, int],
    type_total: int,
    strings: dict[str, int | None],
) -> list[dict[str, Any]]:
    section = sections["images"]
    record = 32 + 2 * widths["type_definition"]
    count = int(section["size"] or 0) // record if section["size"] else 0
    rows = []
    for index in range(min(count, _MAX_ROWS)):
        at = int(section["offset"] or 0) + index * record
        start = _read_index(data, at + 8, widths["type_definition"])
        amount = struct.unpack_from("<I", data, at + 8 + widths["type_definition"])[0]
        if amount and (start < 0 or start + amount > type_total):
            raise ValueError(f"image {index} type range is out of range")
        rows.append(
            {
                "name": _string(
                    data, int(strings["offset"] or 0), struct.unpack_from("<i", data, at)[0]
                ),
                "type_start": start,
                "type_count": amount,
            }
        )
    return rows


def _named(
    data: bytes,
    sections: dict[str, dict[str, int | None]],
    name: str,
    record: int,
    widths: dict[str, int],
    total: int,
    strings: dict[str, int | None],
    *,
    method: bool = False,
) -> list[dict[str, Any]]:
    section = sections[name]
    count = int(section["size"] or 0) // record if section["size"] else 0
    rows = []
    for index in range(min(count, _MAX_ROWS)):
        at = int(section["offset"] or 0) + index * record
        owner = _read_index(
            data, at + (8 if method else 4), widths["type" if method else "type_definition"]
        )
        rows.append(
            {
                "name": _string(
                    data, int(strings["offset"] or 0), struct.unpack_from("<i", data, at)[0]
                ),
                ("method" if method else "declaring_type"): owner,
            }
        )
    return rows


def _literals(
    data: bytes,
    sections: dict[str, dict[str, int | None]],
    counted: bool,
) -> list[dict[str, Any]]:
    section = sections["stringLiterals"]
    payload = sections["stringLiteralData"]
    record = 4 if counted else 8
    count = int(section["size"] or 0) // record if section["size"] else 0
    if counted:
        count = max(0, count - 1)
    rows = []
    for index in range(min(count, _MAX_ROWS)):
        at = int(section["offset"] or 0) + index * record
        if counted:
            start = struct.unpack_from("<i", data, at)[0]
            end = struct.unpack_from("<i", data, at + 4)[0]
            length = end - start
        else:
            start = struct.unpack_from("<i", data, at + 4)[0]
            length = struct.unpack_from("<I", data, at)[0]
        if start < 0 or length < 0 or start + length > int(payload["size"] or 0):
            raise ValueError(f"string literal {index} is out of range")
        raw = data[
            int(payload["offset"] or 0) + start : int(payload["offset"] or 0) + start + length
        ]
        try:
            rows.append({"value": raw.decode("utf-8"), "value_base64": None})
        except UnicodeDecodeError:
            rows.append({"value": None, "value_base64": base64.b64encode(raw).decode("ascii")})
    return rows


def _read_index(data: bytes, offset: int, width: int) -> int:
    if width == 1:
        value = data[offset]
        return -1 if value == 0xFF else value
    if width == 2:
        value = struct.unpack_from("<H", data, offset)[0]
        return -1 if value == 0xFFFF else value
    return int(struct.unpack_from("<i", data, offset)[0])


__all__ = ["Il2CppMetadataProvider"]
