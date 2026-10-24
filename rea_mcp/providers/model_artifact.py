"""Static GGUF and safetensors header inspection."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="model-artifact", name="REA-Python model artifacts", version="1")
_MAX_HEADER = 100 * 1024 * 1024
_MAX_METADATA = 4096
_MAX_TENSORS = 100_000


class ModelArtifactProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="inspect_model_artifact",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=(
                    "Headers only; tensor payloads and model behavior are not inspected.",
                ),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        suffix = target.path.lower()
        if suffix.endswith((".gguf", ".safetensors")):
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported",
            reason="not a GGUF or safetensors artifact",
            code="target_format_unsupported",
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: Any,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del profile
        if operation != "inspect_model_artifact":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        try:
            data = Path(target.path).read_bytes()
        except OSError as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        if len(data) > _MAX_HEADER:
            return err(
                AnalysisInputError(operation=operation, message="model header exceeds 100 MB")
            )
        try:
            if data[:4] == b"GGUF":
                result = _gguf(data, parameters)
            elif target.path.lower().endswith(".safetensors"):
                result = _safetensors(data, parameters)
            else:
                return err(
                    AnalysisInputError(operation=operation, message="unrecognized model header")
                )
        except (ValueError, struct.error, json.JSONDecodeError) as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        return ok(AnalysisExecution(result=result, provider=_PROVIDER))


def _gguf(data: bytes, parameters: dict[str, Any]) -> dict[str, Any]:
    version, tensors, metadata_count = struct.unpack_from("<IQQ", data, 4)
    cursor = 24
    metadata: dict[str, Any] = {}
    for _ in range(min(metadata_count, _MAX_METADATA)):
        key, cursor = _gguf_string(data, cursor)
        kind = struct.unpack_from("<I", data, cursor)[0]
        cursor += 4
        value, cursor = _gguf_value(data, cursor, kind, depth=0)
        metadata[key] = value
    tensor_rows = []
    for _ in range(min(tensors, _MAX_TENSORS)):
        name, cursor = _gguf_string(data, cursor)
        dimensions = struct.unpack_from("<I", data, cursor)[0]
        cursor += 4
        shape = list(struct.unpack_from(f"<{dimensions}Q", data, cursor)) if dimensions else []
        cursor += 8 * dimensions
        kind, offset = struct.unpack_from("<IQ", data, cursor)
        cursor += 12
        tensor_rows.append({"name": name, "shape": shape, "type_id": kind, "offset": offset})
    result = {
        "format": "gguf",
        "version": version,
        "metadata": metadata,
        "metadata_count": len(metadata),
        "tensors": tensor_rows[: min(len(tensor_rows), 1000)],
        "tensor_count": len(tensor_rows),
        "header_bytes": cursor,
        "header_sha256": hashlib.sha256(data[:cursor]).hexdigest(),
        "sha256": None,
        "limitations": ("Header only; tensor payloads and inference behavior are not inspected.",),
    }
    if parameters.get("hash") == "full":
        result["sha256"] = hashlib.sha256(data).hexdigest()
    return result


def _safetensors(data: bytes, parameters: dict[str, Any]) -> dict[str, Any]:
    header_size = struct.unpack_from("<Q", data, 0)[0]
    if header_size > _MAX_HEADER - 8 or 8 + header_size > len(data):
        raise ValueError("safetensors header is truncated")
    header = json.loads(data[8 : 8 + header_size])
    metadata = header.pop("__metadata__", None) or {}
    tensors = []
    for name, item in list(header.items())[:1000]:
        if isinstance(item, dict):
            tensors.append(
                {
                    "name": name,
                    "dtype": item.get("dtype"),
                    "shape": item.get("shape"),
                    "data_offsets": item.get("data_offsets"),
                }
            )
    result = {
        "format": "safetensors",
        "metadata": metadata,
        "tensors": tensors,
        "tensor_count": len(header),
        "header_bytes": 8 + header_size,
        "header_sha256": hashlib.sha256(data[: 8 + header_size]).hexdigest(),
        "sha256": None,
        "limitations": ("Header only; tensor payloads and inference behavior are not inspected.",),
    }
    if parameters.get("hash") == "full":
        result["sha256"] = hashlib.sha256(data).hexdigest()
    return result


def _gguf_string(data: bytes, cursor: int) -> tuple[str, int]:
    length = struct.unpack_from("<Q", data, cursor)[0]
    cursor += 8
    if length > 16 * 1024 * 1024 or cursor + length > len(data):
        raise ValueError("GGUF string is truncated")
    return data[cursor : cursor + length].decode("utf-8", errors="replace"), cursor + length


def _gguf_value(data: bytes, cursor: int, kind: int, depth: int) -> tuple[Any, int]:
    if depth > 32:
        raise ValueError("GGUF metadata nesting is too deep")
    if kind == 0:
        return int.from_bytes(data[cursor : cursor + 1], "little"), cursor + 1
    if kind == 1:
        return int.from_bytes(data[cursor : cursor + 1], "little", signed=True), cursor + 1
    if kind == 2:
        return int.from_bytes(data[cursor : cursor + 2], "little"), cursor + 2
    if kind == 3:
        return int.from_bytes(data[cursor : cursor + 2], "little", signed=True), cursor + 2
    if kind == 4:
        return struct.unpack_from("<I", data, cursor)[0], cursor + 4
    if kind == 5:
        return struct.unpack_from("<i", data, cursor)[0], cursor + 4
    if kind == 6:
        return struct.unpack_from("<f", data, cursor)[0], cursor + 4
    if kind == 7:
        return int.from_bytes(data[cursor : cursor + 1], "little") != 0, cursor + 1
    if kind == 8:
        return _gguf_string(data, cursor)
    if kind == 9:
        inner, cursor = _gguf_value(
            data, cursor, struct.unpack_from("<I", data, cursor)[0], depth + 1
        )
        count = struct.unpack_from("<Q", data, cursor)[0]
        cursor += 8
        values = []
        for _ in range(min(count, 256)):
            value, cursor = _gguf_value(data, cursor, inner, depth + 1)
            values.append(value)
        return values, cursor
    if kind == 10:
        return int.from_bytes(data[cursor : cursor + 8], "little"), cursor + 8
    if kind == 11:
        return int.from_bytes(data[cursor : cursor + 8], "little", signed=True), cursor + 8
    if kind == 12:
        return struct.unpack_from("<d", data, cursor)[0], cursor + 8
    raise ValueError(f"unknown GGUF metadata type {kind}")


__all__ = ["ModelArtifactProvider"]
