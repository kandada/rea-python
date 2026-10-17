"""Provider backed by Rizin/radare2 via ``rzpipe`` (caller-supplied, optional).

When ``rzpipe`` (or the Rizin executable it talks to) is unavailable, every
operation reports an actionable capability error instead of failing the import.
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
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .external import optional_import, resolve_tool
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="rizin", name="REA-Python Rizin adapter", version="1")
_OPERATIONS = ("analyze", "function", "decompile", "search", "xrefs", "instructions")
_TOOL_ENV = "REA_RIZIN"


class RizinProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        available, reason = self._availability()
        effects = CapabilityEffects(launches_process=True)
        return tuple(
            CapabilityDescriptor(
                operation=operation,
                provider=_PROVIDER,
                available=available,
                reason=reason,
                effects=effects,
                limitations=(
                    "Output depth and decompiler availability follow the caller's Rizin build.",
                ),
            )
            for operation in _OPERATIONS
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format in ("elf", "pe", "mach-o", "mach-o-universal", "raw-binary"):
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported", reason="Rizin requires a native binary", code="target_format_unsupported"
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del profile
        if operation not in _OPERATIONS:
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        available, reason = self._availability()
        if not available:
            return err(
                AnalysisCapabilityUnavailableError(
                    message=reason or "Rizin is unavailable",
                    provider_id=_PROVIDER.id,
                    operation=operation,
                    reason="provider_unavailable",
                    remediation_action="Install rzpipe and Rizin, or set REA_RIZIN to an absolute path.",
                )
            )
        import rzpipe

        pipe = rzpipe.open(target.path)
        try:
            pipe.cmd("aaa")
            result = _dispatch(pipe, operation, parameters)
        finally:
            pipe.close()
        return ok(
            AnalysisExecution(
                result=result,
                provider=_PROVIDER,
                limitations=("Analysis is produced by the caller's Rizin build.",),
            )
        )

    def _availability(self) -> tuple[bool, str | None]:
        if optional_import("rzpipe") is None:
            return False, "the optional 'rzpipe' package is not installed"
        resolution = resolve_tool(("rizin",), _TOOL_ENV)
        if not resolution.available:
            return False, resolution.reason
        return True, None


def _dispatch(pipe: Any, operation: str, parameters: dict[str, Any]) -> dict[str, Any]:
    if operation == "analyze":
        info = pipe.cmdj("ij") or {}
        return {
            "arch": (info.get("bin") or {}).get("arch"),
            "bits": (info.get("bin") or {}).get("bits"),
            "os": (info.get("bin") or {}).get("os"),
            "entry": (info.get("bin") or {}).get("baddr"),
        }
    if operation == "function":
        selector = str(parameters.get("function", "main"))
        return {
            "functions": _limited(pipe.cmdj("aflj") or [], int(parameters.get("limit", 200))),
            "selector": selector,
        }
    if operation == "decompile":
        selector = str(parameters.get("function", "main"))
        return {"pseudocode": pipe.cmd(f"pdc @ {selector}")}
    if operation == "search":
        needle = str(parameters.get("query", ""))
        return {
            "matches": _limited(pipe.cmdj(f"/j {needle}") or [], int(parameters.get("limit", 100)))
        }
    if operation == "xrefs":
        selector = str(parameters.get("address", parameters.get("function", "main")))
        return {
            "xrefs": _limited(
                pipe.cmdj(f"axtj @ {selector}") or [], int(parameters.get("limit", 200))
            )
        }
    if operation == "instructions":
        selector = str(parameters.get("address", "entry0"))
        count = int(parameters.get("count", 64))
        return {"instructions": pipe.cmdj(f"pdj {count} @ {selector}") or []}
    return {}


def _limited(items: list[Any], limit: int) -> list[Any]:
    return items[: max(0, limit)]


__all__ = ["RizinProvider"]
