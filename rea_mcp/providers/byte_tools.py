"""Static byte reads/search/address mapping and file entropy."""

from __future__ import annotations

import hashlib
import math
from pathlib import Path
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .formats.elf import parse_elf
from .formats.macho import parse_macho
from .formats.pe import parse_pe
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="byte-tools", name="REA-Python byte tools", version="1")
_ENTROPY_PROVIDER = ProviderIdentity(id="byte-entropy", name="REA-Python byte entropy", version="1")
_MAX_READ = 1_048_576
_MAX_MATCHES = 1000
_MAX_BLOCKS = 32768


class NativeBytesProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return tuple(
            CapabilityDescriptor(
                operation=operation,
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=("Static file mapping only; loaded runtime memory is not read.",),
            )
            for operation in ("read_bytes", "search_bytes", "address_to_file_offset")
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format in ("pe", "elf", "mach-o"):
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported", reason="not a mapped executable", code="target_format_unsupported"
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del profile
        if operation not in ("read_bytes", "search_bytes", "address_to_file_offset"):
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        try:
            data = Path(target.path).read_bytes()
        except OSError as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        mapping = _mapping(data, target.format)
        if operation == "address_to_file_offset":
            try:
                address = _address(parameters.get("address"))
            except ValueError as cause:
                return err(AnalysisInputError(operation=operation, message=str(cause)))
            mapped = _address_to_offset(mapping, address)
            if mapped is None:
                return err(
                    AnalysisInputError(
                        operation=operation,
                        message=f"address {address:#x} is not mapped by a file-backed region",
                    )
                )
            return ok(
                AnalysisExecution(
                    result={
                        "address": f"0x{address:x}",
                        "file_offset": mapped[0],
                        "region": mapped[1],
                    },
                    provider=_PROVIDER,
                )
            )
        if operation == "read_bytes":
            try:
                address = _address(parameters.get("address"))
                length = min(max(1, int(parameters.get("length") or 256)), _MAX_READ)
            except (ValueError, TypeError) as cause:
                return err(AnalysisInputError(operation=operation, message=str(cause)))
            mapped = _address_to_offset(mapping, address)
            if mapped is None:
                return err(
                    AnalysisInputError(
                        operation=operation,
                        message=f"address {address:#x} is not mapped by a file-backed region",
                    )
                )
            offset, region = mapped
            raw = bytes(data[offset : offset + length])
            return ok(
                AnalysisExecution(
                    result={
                        "address": f"0x{address:x}",
                        "file_offset": offset,
                        "requested_length": length,
                        "returned_length": len(raw),
                        "hex": raw.hex(),
                        "region": region,
                    },
                    provider=_PROVIDER,
                    limitations=("Bytes are read from the file, not live memory.",),
                )
            )
        try:
            pattern, mask = _pattern(parameters.get("pattern"), parameters.get("mask"))
            start = int(parameters.get("start") or 0)
            end = int(parameters.get("end") or len(data))
            limit = min(max(1, int(parameters.get("limit") or 100)), _MAX_MATCHES)
        except (ValueError, TypeError) as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        start = max(0, start)
        end = min(len(data), max(start, end))
        matches = _search(data, pattern, mask, start, end, limit, mapping)
        return ok(
            AnalysisExecution(
                result={
                    "pattern": parameters.get("pattern"),
                    "match_count": len(matches),
                    "matches": matches,
                    "truncated": len(matches) >= limit,
                },
                provider=_PROVIDER,
                limitations=(
                    "Search is a bounded file scan; it does not inspect decompressed or live memory.",
                ),
            )
        )


class ByteEntropyProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _ENTROPY_PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="inspect_byte_entropy",
                provider=_ENTROPY_PROVIDER,
                effects=CapabilityEffects(),
                limitations=("Entropy cannot distinguish compression from encryption.",),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        return TargetSupport("supported")

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del profile
        if operation != "inspect_byte_entropy":
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
            block = int(parameters.get("block_size") or 4096)
            offset = max(0, int(parameters.get("offset") or 0))
            length = int(parameters.get("length") or max(0, len(data) - offset))
        except (ValueError, TypeError) as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        if block < 256 or block > 65536 or block & (block - 1):
            return err(
                AnalysisInputError(
                    operation=operation,
                    message="block_size must be a power of two from 256 to 65536",
                )
            )
        length = min(max(0, length), max(0, len(data) - offset))
        if length // block > _MAX_BLOCKS:
            return err(
                AnalysisInputError(
                    operation=operation,
                    message=f"window produces more than {_MAX_BLOCKS} entropy blocks",
                )
            )
        window = bytes(data[offset : offset + length])
        blocks = [
            {
                "offset": offset + index,
                "length": len(window[index : index + block]),
                "entropy": round(_entropy(window[index : index + block]), 6),
            }
            for index in range(0, len(window), block)
        ]
        return ok(
            AnalysisExecution(
                result={
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "byte_length": len(data),
                    "entropy": round(_entropy(data), 6),
                    "window": {"offset": offset, "length": length, "block_size": block},
                    "blocks": blocks,
                    "block_count": len(blocks),
                    "high_runs": _runs(blocks, lambda value: value >= 7.2),
                    "low_runs": _runs(blocks, lambda value: value <= 1.0),
                },
                provider=_ENTROPY_PROVIDER,
            )
        )


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts if count)


def _runs(blocks: list[dict[str, Any]], predicate: Any) -> list[dict[str, int]]:
    runs: list[dict[str, int]] = []
    start = None
    for index, block in enumerate(blocks):
        if predicate(float(block["entropy"])):
            if start is None:
                start = index
        elif start is not None:
            runs.append(
                {
                    "start_offset": blocks[start]["offset"],
                    "end_offset": blocks[index - 1]["offset"] + blocks[index - 1]["length"],
                }
            )
            start = None
    if start is not None:
        last = blocks[-1]
        runs.append(
            {"start_offset": blocks[start]["offset"], "end_offset": last["offset"] + last["length"]}
        )
    return runs


def _address(value: Any) -> int:
    if isinstance(value, int):
        return value
    text = str(value).strip()
    return int(text, 0)


def _pattern(value: Any, mask_value: Any) -> tuple[bytes, bytes | None]:
    text = str(value or "").replace(" ", "")
    if not text:
        raise ValueError("pattern is required")
    if len(text) % 2:
        raise ValueError("pattern must contain whole hex bytes")
    pattern = bytearray()
    mask = bytearray()
    for index in range(0, len(text), 2):
        pair = text[index : index + 2]
        if pair in ("??", "**"):
            pattern.append(0)
            mask.append(0)
        else:
            pattern.append(int(pair, 16))
            mask.append(0xFF)
    if mask_value:
        mask_text = str(mask_value).replace(" ", "")
        if len(mask_text) != len(text):
            raise ValueError("mask must have the same byte length as pattern")
        mask = bytearray(
            int(mask_text[index : index + 2], 16) for index in range(0, len(mask_text), 2)
        )
    return bytes(pattern), bytes(mask) if any(byte != 0xFF for byte in mask) else None


def _mapping(data: bytes, target_format: str) -> list[dict[str, Any]]:
    regions: list[dict[str, Any]] = []
    if target_format == "pe":
        pe_info = parse_pe(data)
        if pe_info is None:
            raise ValueError("Not a PE image")
        for pe_section in pe_info.sections:
            regions.append(
                {
                    "name": pe_section.name,
                    "address": pe_info.image_base + pe_section.virtual_address,
                    "size": max(pe_section.virtual_size, pe_section.size_of_raw_data),
                    "offset": pe_section.pointer_to_raw_data,
                    "file_size": pe_section.size_of_raw_data,
                }
            )
    elif target_format == "elf":
        elf_info = parse_elf(data)
        if elf_info is None:
            raise ValueError("Not an ELF image")
        for elf_section in elf_info.sections:
            if elf_section.size and elf_section.addr:
                regions.append(
                    {
                        "name": elf_section.name or None,
                        "address": elf_section.addr,
                        "size": elf_section.size,
                        "offset": elf_section.offset,
                        "file_size": elf_section.size,
                    }
                )
    else:
        macho_info = parse_macho(data)
        if macho_info is None:
            raise ValueError("Not a Mach-O image")
        for segment in macho_info.segments:
            regions.append(
                {
                    "name": segment.name or None,
                    "address": segment.vmaddr,
                    "size": segment.vmsize,
                    "offset": segment.fileoff,
                    "file_size": segment.filesize,
                }
            )
    return regions


def _address_to_offset(
    regions: list[dict[str, Any]], address: int
) -> tuple[int, dict[str, Any]] | None:
    for region in regions:
        start = int(region["address"])
        size = int(region["size"])
        if start <= address < start + size:
            delta = address - start
            if delta >= int(region["file_size"]):
                return None
            return int(region["offset"]) + delta, region
    return None


def _search(
    data: bytes,
    pattern: bytes,
    mask: bytes | None,
    start: int,
    end: int,
    limit: int,
    regions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    cursor = start
    while cursor <= end - len(pattern) and len(matches) < limit:
        if mask is None:
            found = data.find(pattern, cursor, end)
            if found < 0:
                break
        else:
            found = -1
            for candidate in range(cursor, end - len(pattern) + 1):
                if all(
                    (data[candidate + index] & mask[index]) == (pattern[index] & mask[index])
                    for index in range(len(pattern))
                ):
                    found = candidate
                    break
            if found < 0:
                break
        matches.append({"file_offset": found, "address": _offset_to_address(regions, found)})
        cursor = found + 1
    return matches


def _offset_to_address(regions: list[dict[str, Any]], offset: int) -> str | None:
    for region in regions:
        start = int(region["offset"])
        size = int(region["file_size"])
        if start <= offset < start + size:
            return f"0x{int(region['address']) + offset - start:x}"
    return None


__all__ = ["ByteEntropyProvider", "NativeBytesProvider"]
