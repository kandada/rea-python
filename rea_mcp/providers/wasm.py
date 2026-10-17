"""Built-in WebAssembly artifact provider.

Structural inspection (sections, import/export counts) is pure Python and always
available; decoded WAT text is produced only when a caller-supplied WABT
(``wasm2wat``) is present.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from ..process.supervision import run_owned_process
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .external import resolve_shell_command
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="wasm", name="REA-Python WASM artifacts", version="1")

_SECTION_NAMES = {
    0: "custom",
    1: "type",
    2: "import",
    3: "function",
    4: "table",
    5: "memory",
    6: "global",
    7: "export",
    8: "start",
    9: "element",
    10: "code",
    11: "data",
    12: "datacount",
}


class WasmArtifactProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="inspect_wasm_artifact",
                provider=_PROVIDER,
                effects=CapabilityEffects(launches_process=True),
                limitations=("Decoded WAT requires a caller-supplied wasm2wat.",),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format == "wasm":
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported", reason="not a WASM module", code="target_format_unsupported"
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del profile
        if operation != "inspect_wasm_artifact":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        try:
            data = Path(target.path).read_bytes()
        except OSError as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))

        parsed = _parse_sections(data)
        if parsed is None:
            return err(AnalysisInputError(operation=operation, message="Not a valid WASM module"))
        version, sections = parsed

        wat: str | None = None
        wat_truncated = False
        tool_profile = "structural-only"
        wat_tool = resolve_shell_command("wasm2wat")
        if wat_tool.available:
            tool_profile = "wasm2wat"
            result = run_owned_process(
                ["wasm2wat", target.path], timeout=60, operation=operation, max_output_bytes=262144
            )
            if result.ok:
                wat = result.value.stdout
                wat_truncated = result.value.stdout_truncated

        return ok(
            AnalysisExecution(
                result={
                    "valid": True,
                    "version": version,
                    "sections": sections,
                    "section_count": len(sections),
                    "wat": wat,
                    "wat_truncated": wat_truncated,
                    "tool_profile": tool_profile,
                },
                provider=_PROVIDER,
                limitations=(
                    ("Decoded WAT was not available; install WABT for wasm2wat.",)
                    if wat is None
                    else ()
                ),
            )
        )


def _parse_sections(data: bytes) -> tuple[int, list[dict[str, Any]]] | None:
    if len(data) < 8 or data[:4] != b"\x00asm":
        return None
    version = int.from_bytes(data[4:8], "little")
    offset = 8
    sections: list[dict[str, Any]] = []
    while offset < len(data):
        section_id = data[offset]
        offset += 1
        size, offset = _read_uleb(data, offset)
        if size is None or offset + size > len(data):
            return version, sections
        sections.append(
            {
                "id": section_id,
                "name": _SECTION_NAMES.get(section_id, f"section-{section_id}"),
                "size": size,
            }
        )
        offset += size
    return version, sections


def _read_uleb(data: bytes, offset: int) -> tuple[int | None, int]:
    result = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return result, offset
        shift += 7
        if shift > 63:
            return None, offset
    return None, offset


__all__ = ["WasmArtifactProvider"]
