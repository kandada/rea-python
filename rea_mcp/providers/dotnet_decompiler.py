"""Optional C# decompilation through a caller-supplied ``ilspycmd``."""

from __future__ import annotations

import os
import shlex
from typing import Any

from ..domain.analysis_error import (
    AnalysisCapabilityUnavailableError,
    AnalysisError,
    AnalysisInputError,
)
from ..domain.analysis_profile import ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from ..process.supervision import run_owned_process
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .external import ToolResolution, resolve_tool
from .paging import page_lines
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="ilspy", name="REA-Python C# decompiler (ilspycmd)", version="1")


class CSharpDecompilerProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def _resolution(self) -> ToolResolution:
        configured = os.environ.get("REA_ILSPY_CMD_PATH")
        if configured:
            return resolve_tool((configured,), None)
        return resolve_tool(("ilspycmd",), "REA_ILSPY")

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        available, reason = self._resolution().available, self._resolution().reason
        return (
            CapabilityDescriptor(
                operation="decompile_managed_csharp",
                provider=_PROVIDER,
                available=available,
                reason=reason,
                effects=CapabilityEffects(launches_process=True),
                limitations=(
                    "Optional caller-supplied ilspycmd; C# is a decompiler view, not canonical IL.",
                ),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format == "pe":
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported",
            reason="C# decompilation requires a PE image",
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
        if operation != "decompile_managed_csharp":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        resolution = self._resolution()
        if not resolution.available or resolution.path is None:
            return err(
                AnalysisCapabilityUnavailableError(
                    message=resolution.reason or "ilspycmd is unavailable",
                    provider_id=_PROVIDER.id,
                    operation=operation,
                    reason="provider_unavailable",
                )
            )
        type_name = str(parameters.get("type") or parameters.get("type_name") or "").strip()
        method = str(parameters.get("method") or "").strip() or None
        if not type_name:
            return err(
                AnalysisInputError(
                    operation=operation,
                    message="decompile_managed_csharp requires an exact type name",
                )
            )
        argv = [*shlex.split(resolution.path), "-t", type_name]
        if method:
            argv.extend(["-m", method])
        argv.append(target.path)
        result = run_owned_process(
            argv,
            timeout=float(parameters.get("timeout") or 120.0),
            operation=operation,
            max_output_bytes=4 * 1024 * 1024,
        )
        if not result.ok:
            return err(result.error)
        source = result.value.stdout
        page = page_lines(
            source,
            offset=int(parameters.get("offset") or 0),
            limit=int(parameters.get("limit") or 500),
        )
        return ok(
            AnalysisExecution(
                result={
                    "language": "csharp",
                    "decompiler": "ilspycmd",
                    "type": type_name,
                    "method": method,
                    "source": page["text"],
                    "source_bytes": len(source.encode("utf-8")),
                    "source_line_total": page["line_total"],
                    "source_offset": page["offset"],
                    "next_offset": page["next_offset"],
                    "stderr_tail": result.value.stderr[-2000:],
                },
                provider=self.identity(),
                limitations=(
                    "C# output follows the caller's ilspycmd version and is analyst-facing decompilation, not canonical IL.",
                ),
            )
        )


__all__ = ["CSharpDecompilerProvider"]
