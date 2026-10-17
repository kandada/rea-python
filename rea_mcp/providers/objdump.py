"""Provider backed by GNU objdump (caller-supplied).

Reports an actionable capability error when ``objdump`` is not available; runs
only against a caller-supplied executable.
"""

from __future__ import annotations

from typing import Any

from ..domain.analysis_error import (
    AnalysisCapabilityUnavailableError,
    AnalysisError,
    AnalysisInputError,
)
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from ..process.supervision import run_owned_process
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .external import resolve_tool
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="objdump", name="REA-Python objdump adapter", version="1")
_TOOL_ENV = "REA_OBJDUMP"


class ObjdumpProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        available, reason = self._tool()
        effects = CapabilityEffects(launches_process=True)
        limitations = ("Disassembly depth and syntax follow the caller's objdump build.",)
        return (
            CapabilityDescriptor(
                operation="inspect_with_objdump",
                provider=_PROVIDER,
                available=available,
                reason=reason,
                effects=effects,
                limitations=limitations,
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format in ("elf", "pe", "mach-o", "mach-o-universal", "raw-binary"):
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported",
            reason="objdump requires a native binary",
            code="target_format_unsupported",
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del profile
        available, reason = self._tool()
        if not available:
            return err(
                AnalysisCapabilityUnavailableError(
                    message=reason or "objdump is unavailable",
                    provider_id=_PROVIDER.id,
                    operation=operation,
                    reason="provider_unavailable",
                    remediation_action="Install binutils/objdump or set REA_OBJDUMP to an absolute path.",
                )
            )
        tool = self._tool_path()
        assert tool is not None
        if operation == "inspect_with_objdump":
            return self._headers(tool, target)
        return err(
            AnalysisInputError(operation=operation, message=f"unsupported operation {operation}")
        )

    def _headers(self, tool: str, target: BinaryTarget) -> Result[AnalysisExecution, AnalysisError]:
        file_result = run_owned_process(
            [tool, "-f", target.path], timeout=60, operation="inspect_with_objdump"
        )
        if not file_result.ok:
            return err(file_result.error)
        section_result = run_owned_process(
            [tool, "-h", target.path], timeout=60, operation="inspect_with_objdump"
        )
        if not section_result.ok:
            return err(section_result.error)
        sections = _parse_sections(section_result.value.stdout)
        return ok(
            AnalysisExecution(
                result={
                    "file": file_result.value.stdout.strip(),
                    "sections": sections,
                },
                provider=_PROVIDER,
                limitations=("Text follows the caller's objdump locale and version.",),
            )
        )

    def _tool(self) -> tuple[bool, str | None]:
        resolution = resolve_tool(("objdump",), _TOOL_ENV)
        return resolution.available, resolution.reason

    def _tool_path(self) -> str | None:
        return resolve_tool(("objdump",), _TOOL_ENV).path


def _parse_sections(text: str) -> list[dict[str, Any]]:
    sections: list[dict[str, Any]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("Sections") or stripped.startswith("Idx"):
            continue
        parts = stripped.split()
        if len(parts) >= 2 and parts[0].isdigit():
            sections.append({"index": int(parts[0]), "name": parts[1]})
    return sections


__all__ = ["ObjdumpProvider"]
