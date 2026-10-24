"""Static CPython .pyc header and marshalled code-object inspection."""

from __future__ import annotations

import hashlib
import marshal
import types
from pathlib import Path
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="python-pyc", name="REA-Python CPython pyc", version="1")
_MAX_OBJECTS = 1000
_MAX_CONST = 256
_MAX_TEXT = 512

# Stable CPython magic numbers for the supported 3.7-3.13 line. Patch releases
# reuse a magic except in rare interpreter transitions.
_MAGIC_VERSIONS = {
    3394: "3.7",
    3395: "3.7",
    3400: "3.8",
    3413: "3.8",
    3425: "3.9",
    3439: "3.10",
    3495: "3.11",
    3531: "3.12",
    3571: "3.13",
    3572: "3.13",
}


class PythonPycProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="inspect_python_pyc",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=(
                    "The marshal graph is inspected only when this interpreter understands its layout; source is not recovered.",
                ),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.path.lower().endswith(".pyc"):
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported", reason="not a .pyc file", code="target_format_unsupported"
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: Any,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del parameters, profile
        if operation != "inspect_python_pyc":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        try:
            data = Path(target.path).read_bytes()
        except OSError as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        if len(data) < 16:
            return err(AnalysisInputError(operation=operation, message="truncated .pyc header"))
        magic = int.from_bytes(data[:2], "little")
        flags = int.from_bytes(data[4:8], "little")
        header: dict[str, Any] = {
            "magic": magic,
            "python_version": _MAGIC_VERSIONS.get(magic),
            "flags": flags,
            "hash_based": bool(flags & 0x1),
            "check_source": bool(flags & 0x2),
            "source_hash_hex": None,
            "source_mtime": None,
            "source_size": None,
        }
        if flags & 0x1:
            header["source_hash_hex"] = data[8:16].hex()
        else:
            header["source_mtime"] = int.from_bytes(data[8:12], "little")
            header["source_size"] = int.from_bytes(data[12:16], "little")
        try:
            top = marshal.loads(data[16:])
        except Exception as cause:
            return ok(
                AnalysisExecution(
                    result={
                        "header": header,
                        "code_objects": [],
                        "coverage": {"state": "unavailable", "issues": [str(cause)]},
                        "limitations": (
                            "This interpreter cannot decode the marshalled code layout; header facts remain.",
                        ),
                    },
                    provider=_PROVIDER,
                )
            )
        if not isinstance(top, types.CodeType):
            return err(
                AnalysisInputError(
                    operation=operation, message="top-level marshalled object is not code"
                )
            )
        objects: list[dict[str, Any]] = []
        _collect(top, objects)
        return ok(
            AnalysisExecution(
                result={
                    "header": header,
                    "code_objects": objects,
                    "code_count": len(objects),
                    "coverage": {"state": "complete", "issues": []},
                    "limitations": (
                        "Bytecode is not decompiled; marshal layout is interpreted by the running Python version.",
                    ),
                },
                provider=_PROVIDER,
            )
        )


def _collect(top: types.CodeType, objects: list[dict[str, Any]]) -> None:
    queue = [top]
    seen: set[int] = set()
    while queue and len(objects) < _MAX_OBJECTS:
        code = queue.pop(0)
        if id(code) in seen:
            continue
        seen.add(id(code))
        names = [str(value)[:_MAX_TEXT] for value in code.co_names[:64]]
        varnames = [str(value)[:_MAX_TEXT] for value in code.co_varnames[:64]]
        consts = [_const(value) for value in code.co_consts[:_MAX_CONST]]
        objects.append(
            {
                "name": code.co_name,
                "qualname": getattr(code, "co_qualname", None),
                "filename": code.co_filename,
                "argcount": code.co_argcount,
                "posonlyargcount": getattr(code, "co_posonlyargcount", 0),
                "kwonlyargcount": code.co_kwonlyargcount,
                "flags": code.co_flags,
                "names": names,
                "varnames": varnames,
                "const_count": len(code.co_consts),
                "consts": consts,
                "code_size": len(code.co_code),
                "code_sha256": hashlib.sha256(code.co_code).hexdigest(),
            }
        )
        queue.extend(value for value in code.co_consts if isinstance(value, types.CodeType))
    if queue:
        objects.append({"name": "<truncated>", "code_size": 0, "consts": []})


def _const(value: Any) -> dict[str, Any]:
    if isinstance(value, types.CodeType):
        return {"type": "code", "name": value.co_name}
    if isinstance(value, str):
        return {"type": "str", "value": value[:_MAX_TEXT], "length": len(value)}
    if isinstance(value, (int, float, complex, bool)) or value is None:
        return {
            "type": type(value).__name__,
            "value": value if not isinstance(value, int) or value.bit_length() <= 256 else None,
        }
    if isinstance(value, (bytes, bytearray)):
        return {
            "type": "bytes",
            "length": len(value),
            "sha256": hashlib.sha256(bytes(value)).hexdigest(),
        }
    if isinstance(value, tuple):
        return {"type": "tuple", "length": len(value)}
    return {"type": type(value).__name__}


__all__ = ["PythonPycProvider"]
