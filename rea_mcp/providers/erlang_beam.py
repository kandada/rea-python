"""Pure-Python Erlang BEAM IFF chunk inspection."""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="erlang-beam", name="REA-Python Erlang BEAM", version="1")
_MAX_CHUNKS = 64
_MAX_ATOMS = 4096
_MAX_ROWS = 65536


class ErlangBeamProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="inspect_erlang_beam",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=(
                    "BEAM bytecode is not executed; literal/attribute terms are not decoded.",
                ),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.path.lower().endswith(".beam"):
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported", reason="not a BEAM file", code="target_format_unsupported"
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del parameters, profile
        if operation != "inspect_erlang_beam":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        try:
            data = Path(target.path).read_bytes()
        except OSError as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        if len(data) < 12 or data[:4] != b"FOR1" or data[8:12] != b"BEAM":
            return err(AnalysisInputError(operation=operation, message="Not a FOR1/BEAM file"))
        try:
            result = _inspect(data)
        except (ValueError, struct.error) as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        return ok(AnalysisExecution(result=result, provider=_PROVIDER))


def _inspect(data: bytes) -> dict[str, Any]:
    chunks: list[dict[str, Any]] = []
    payloads: dict[str, bytes] = {}
    cursor = 12
    while cursor + 8 <= len(data) and len(chunks) < _MAX_CHUNKS:
        name = data[cursor : cursor + 4].decode("ascii", errors="replace")
        size = int.from_bytes(data[cursor + 4 : cursor + 8], "big")
        start = cursor + 8
        end = start + size
        if end > len(data):
            raise ValueError(f"BEAM chunk {name} extends past the file")
        payload = bytes(data[start:end])
        chunks.append(
            {
                "name": name,
                "offset": start,
                "size": size,
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
        if name not in payloads:
            payloads[name] = payload
        cursor = end + (size & 1)
    if not chunks:
        raise ValueError("BEAM file has no chunks")

    atoms = _atoms(payloads.get("AtU8") or payloads.get("Atom"))
    module = atoms[0] if atoms else None
    exports = _rows(payloads.get("ExpT"), 4, atoms, 0)
    imports = _rows(payloads.get("ImpT"), 3, atoms, 1, module=True)
    lambdas = _lambdas(payloads.get("FunT"), atoms)
    code = _code(payloads.get("Code"))
    return {
        "has_beam": True,
        "module": module,
        "atom_count": len(atoms),
        "atoms": atoms,
        "chunks": chunks,
        "exports": exports,
        "imports": imports,
        "lambdas": lambdas,
        "code": code,
        "limitations": [],
    }


def _atoms(payload: bytes | None) -> list[str]:
    if payload is None or len(payload) < 4:
        return []
    count = int.from_bytes(payload[:4], "little", signed=False)
    if count & 0x80000000:
        # OTP 28 compact atom table; length coding is not implemented.
        return []
    cursor = 4
    atoms: list[str] = []
    while cursor < len(payload) and len(atoms) < min(count, _MAX_ATOMS):
        length = payload[cursor]
        cursor += 1
        raw = payload[cursor : cursor + length]
        if len(raw) != length:
            raise ValueError("truncated BEAM atom")
        atoms.append(raw.decode("utf-8", errors="replace"))
        cursor += length
    return atoms


def _rows(
    payload: bytes | None,
    width: int,
    atoms: list[str],
    atom_offset: int,
    *,
    module: bool = False,
) -> list[dict[str, Any]]:
    if payload is None:
        return []
    rows: list[dict[str, Any]] = []
    cursor = 0
    while cursor + width * 4 <= len(payload) and len(rows) < _MAX_ROWS:
        values = struct.unpack_from(f"<{width}I", payload, cursor)
        cursor += width * 4
        function_index = values[atom_offset]
        item: dict[str, Any] = {
            "function": atoms[function_index - 1] if 1 <= function_index <= len(atoms) else None,
            "function_atom": function_index,
            "arity": values[1],
        }
        if module:
            module_index = values[0]
            item["module"] = atoms[module_index - 1] if 1 <= module_index <= len(atoms) else None
            item["module_atom"] = module_index
        else:
            item["label"] = values[2]
            item["code_offset"] = values[3]
        rows.append(item)
    return rows


def _lambdas(payload: bytes | None, atoms: list[str]) -> list[dict[str, Any]]:
    if payload is None or len(payload) < 4:
        return []
    count = min(int.from_bytes(payload[:4], "little"), _MAX_ROWS)
    cursor = 4
    rows: list[dict[str, Any]] = []
    while cursor + 24 <= len(payload) and len(rows) < count:
        function, arity, label, index = struct.unpack_from("<IIII", payload, cursor)
        cursor += 16
        num_free = int.from_bytes(payload[cursor : cursor + 4], "little")
        cursor += 4 + 4 * num_free
        rows.append(
            {
                "function": atoms[function - 1] if 1 <= function <= len(atoms) else None,
                "function_atom": function,
                "arity": arity,
                "label": label,
                "index": index,
                "num_free": num_free,
            }
        )
    return rows


def _code(payload: bytes | None) -> dict[str, Any] | None:
    if payload is None or len(payload) < 20:
        return None
    info_size, version, max_opcode, labels, functions = struct.unpack_from("<IIIII", payload, 0)
    return {
        "info_size": info_size,
        "instruction_set": version,
        "max_opcode": max_opcode,
        "label_count": labels,
        "function_count": functions,
        "code_size": max(0, len(payload) - info_size),
    }


__all__ = ["ErlangBeamProvider"]
