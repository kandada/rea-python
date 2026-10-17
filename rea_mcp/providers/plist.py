"""Built-in property-list provider (XML and binary plists, pure Python)."""

from __future__ import annotations

import plistlib
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="plist", name="REA-Python property lists", version="1")


class PlistProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="inspect_plist",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=(
                    "The complete value tree is not returned; only a bounded projection.",
                ),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format == "plist":
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported", reason="not a property list", code="target_format_unsupported"
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del profile, parameters
        if operation != "inspect_plist":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        try:
            with open(target.path, "rb") as handle:
                data = handle.read()
            plist_format = plistlib.FMT_BINARY if data[:6] == b"bplist" else plistlib.FMT_XML
            parsed = plistlib.loads(data)
        except (plistlib.InvalidFileException, ValueError, OSError) as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))

        keys = list(parsed.keys()) if isinstance(parsed, dict) else None
        return ok(
            AnalysisExecution(
                result={
                    "plist_format": "binary" if plist_format == plistlib.FMT_BINARY else "xml",
                    "root_type": type(parsed).__name__,
                    "top_level_keys": keys,
                    "top_level_count": len(keys) if keys is not None else None,
                },
                provider=_PROVIDER,
                limitations=("Values are summarized, not returned verbatim.",),
            )
        )


__all__ = ["PlistProvider"]
