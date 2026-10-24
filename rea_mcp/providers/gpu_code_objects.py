"""Bounded static GPU code-object discovery."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .formats.elf import parse_elf
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="gpu-code-objects", name="REA-Python GPU code objects", version="1")
_FATBIN = b"\x50\xed\x55\xba"


class GpuCodeObjectsProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="inspect_gpu_code_objects",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=(
                    "Object discovery only; SASS/PTX semantics and runtime launch are not analyzed.",
                ),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        return TargetSupport("supported")

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: Any,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del parameters, profile
        if operation != "inspect_gpu_code_objects":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        try:
            data = Path(target.path).read_bytes()
        except OSError as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        objects: list[dict[str, Any]] = []
        if data[:4] == b"\x7fELF":
            elf = parse_elf(data)
            if elf is not None and elf.machine == 190:
                objects.append(
                    {
                        "kind": "cubin",
                        "offset": 0,
                        "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "cubin": _cubin(data),
                    }
                )
            elif elf is not None and elf.machine == 224:
                objects.append(
                    {
                        "kind": "amdgpu",
                        "offset": 0,
                        "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "amdgpu": _amdgpu(data),
                    }
                )
            else:
                objects.append(
                    {
                        "kind": "elf-host",
                        "offset": 0,
                        "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                    }
                )
        cursor = 0
        while True:
            found = data.find(_FATBIN, cursor)
            if found < 0 or len(objects) >= 64:
                break
            objects.extend(_fatbin(data, found))
            cursor = found + 4
        for marker, kind in ((b".version", "ptx"), (b"__hip", "hip"), (b".amdgpu", "amdgpu")):
            index = data.find(marker)
            if index >= 0 and len(objects) < 64:
                item: dict[str, Any] = {
                    "kind": kind,
                    "offset": index,
                    "size": None,
                    "sha256": None,
                }
                if kind == "ptx":
                    item["ptx"] = _ptx(data[index:].decode("utf-8", errors="replace"))
                objects.append(item)
        return ok(
            AnalysisExecution(
                result={
                    "has_gpu_objects": bool(objects),
                    "object_count": len(objects),
                    "objects": objects,
                    "limitations": (
                        "Discovery is marker-based; object contents and launch behavior are not decoded.",
                    ),
                },
                provider=_PROVIDER,
            )
        )


def _fatbin(data: bytes, base: int) -> list[dict[str, Any]]:
    if base + 16 > len(data):
        return [{"kind": "cuda-fatbin", "offset": base, "size": None, "sha256": None}]
    header_size = int.from_bytes(data[base + 6 : base + 8], "little")
    length = int.from_bytes(data[base + 8 : base + 16], "little")
    start = base + header_size
    end = min(len(data), start + length)
    rows: list[dict[str, Any]] = []
    cursor = start
    while cursor + 64 <= end and len(rows) < 64:
        kind = int.from_bytes(data[cursor : cursor + 2], "little")
        width = int.from_bytes(data[cursor + 4 : cursor + 8], "little")
        padded = int.from_bytes(data[cursor + 8 : cursor + 16], "little")
        encoded = int.from_bytes(data[cursor + 16 : cursor + 20], "little")
        flags = int.from_bytes(data[cursor + 40 : cursor + 48], "little")
        target = int.from_bytes(data[cursor + 28 : cursor + 32], "little")
        decoded = int.from_bytes(data[cursor + 56 : cursor + 64], "little")
        if width < 64 or cursor + width > end:
            break
        payload = data[cursor + width : min(end, cursor + width + (encoded if encoded else padded))]
        kind_name = "ptx" if kind == 1 else "cubin" if kind == 2 else "unknown"
        row: dict[str, Any] = {
            "kind": kind_name,
            "offset": cursor + width,
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "target": f"sm_{target}" if kind_name != "unknown" else None,
            "compressed": bool(flags & 0xA000),
            "encoded_size": encoded or padded,
            "decoded_size": decoded or padded,
        }
        if kind_name == "ptx":
            row["ptx"] = _ptx(payload.decode("utf-8", errors="replace"))
        elif kind_name == "cubin":
            row["cubin"] = _cubin(payload)
        rows.append(row)
        advance = width + (padded if padded else len(payload))
        if advance <= 0:
            break
        cursor += advance
    return rows or [{"kind": "cuda-fatbin", "offset": base, "size": None, "sha256": None}]


def _amdgpu(data: bytes) -> dict[str, Any]:
    info = parse_elf(data)
    if info is None:
        return {"kernels": [], "limitations": ["AMDGPU object is not a readable ELF"]}
    metadata = next(
        (section for section in info.sections if section.name == ".amdgpu_metadata"),
        None,
    )
    if metadata is None:
        return {"kernels": [], "limitations": ["No .amdgpu_metadata section"]}
    try:
        import msgpack  # type: ignore[import-untyped]

        payload = msgpack.unpackb(
            data[metadata.offset : metadata.offset + metadata.size],
            raw=False,
            strict_map_key=False,
        )
    except Exception as cause:
        return {"kernels": [], "limitations": [f"AMDGPU metadata decode failed: {cause}"]}
    record = payload.get("amdhsa.kernels") if isinstance(payload, dict) else None
    kernels = []
    for item in record or []:
        if not isinstance(item, dict):
            continue
        kernels.append(
            {
                "name": item.get(".name"),
                "symbol": item.get(".symbol"),
                "sgpr_count": item.get(".sgpr_count"),
                "vgpr_count": item.get(".vgpr_count"),
                "agpr_count": item.get(".agpr_count"),
                "kernarg_segment_size": item.get(".kernarg_segment_size"),
                "group_segment_fixed_size": item.get(".group_segment_fixed_size"),
                "private_segment_fixed_size": item.get(".private_segment_fixed_size"),
            }
        )
    return {"kernels": kernels, "kernel_count": len(kernels), "limitations": []}


def _cubin(data: bytes) -> dict[str, Any]:
    info = parse_elf(data)
    if info is None:
        return {
            "architecture": None,
            "sections": [],
            "limitations": ["CUBIN is not a readable ELF"],
        }
    sections = [
        {"name": section.name, "offset": section.offset, "size": section.size, "type": section.type}
        for section in info.sections
    ]
    parameters: list[dict[str, Any]] = []
    parameter_bytes: int | None = None
    registers: set[int] = set()
    register_conflict = False
    nv_info_records = 0
    for section in info.sections:
        if not section.name.startswith(".nv.info"):
            continue
        if section.offset + section.size > len(data):
            continue
        cursor = section.offset
        end = section.offset + section.size
        while cursor + 4 <= end:
            fmt = data[cursor]
            attribute = data[cursor + 1]
            value = int.from_bytes(data[cursor + 2 : cursor + 4], "little")
            length = value if fmt == 4 else 0
            payload = data[cursor + 4 : min(end, cursor + 4 + length)]
            nv_info_records += 1
            if fmt == 3 and attribute == 0x19:
                parameter_bytes = (
                    value
                    if parameter_bytes is None or parameter_bytes == value
                    else parameter_bytes
                )
                if parameter_bytes is not None and parameter_bytes != value:
                    register_conflict = True
            if fmt == 4 and attribute == 0x17 and len(payload) == 12:
                ordinal = int.from_bytes(payload[4:6], "little")
                offset = int.from_bytes(payload[6:8], "little")
                size = int.from_bytes(payload[8:12], "little") >> 18
                parameters.append(
                    {
                        "ordinal": ordinal,
                        "offset": offset,
                        "size": size,
                        "type": None,
                        "name": None,
                    }
                )
            if fmt == 4 and attribute == 0x2F and len(payload) == 8:
                registers.add(int.from_bytes(payload[4:8], "little"))
            cursor += 4 + length
    parameters.sort(key=lambda row: row["ordinal"])
    complete = (
        not register_conflict
        and len(registers) <= 1
        and [row["ordinal"] for row in parameters] == list(range(len(parameters)))
    )
    return {
        "architecture": info.architecture,
        "machine": info.machine,
        "sections": sections[:128],
        "section_count": len(sections),
        "nv_info_records": nv_info_records,
        "parameter_bytes": parameter_bytes,
        "parameters": parameters[:256],
        "parameter_count": len(parameters) if complete else None,
        "physical_registers": next(iter(registers)) if len(registers) == 1 else None,
        "coverage": "complete" if complete else "partial",
        "limitations": (
            []
            if complete
            else ["CUDA parameter/register declarations are conflicting or incomplete."]
        ),
    }


def _ptx(text: str) -> dict[str, Any]:
    entries = re.findall(r"\\.entry\s+([A-Za-z_$][\w$]*)", text)
    registers = {
        kind: len(set(re.findall(rf"%{kind}\d+", text)))
        for kind in ("r", "rd", "f", "fd", "p", "s", "d", "b")
    }
    version = re.search(r"\\.version\s+([^\s]+)", text)
    target = re.search(r"\\.target\s+([^\s]+)", text)
    return {
        "version": version.group(1) if version else None,
        "target": target.group(1) if target else None,
        "entries": entries[:256],
        "entry_count": len(entries),
        "virtual_registers": {key: value for key, value in registers.items() if value},
        "line_count": text.count("\n") + 1,
    }


__all__ = ["GpuCodeObjectsProvider"]
