"""Provider for EVM bytecode interfaces via ``evmole`` (optional).

Reads a raw or hex carrier and reports dispatch selectors, arguments and state
mutability. Reports an actionable capability error when ``evmole`` is absent.
"""

from __future__ import annotations

from pathlib import Path
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
from .external import optional_import
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="evm", name="REA-Python EVM interface", version="1")


class EvmInterfaceProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        available, reason = self._availability()
        return (
            CapabilityDescriptor(
                operation="inspect_evm_interface",
                provider=_PROVIDER,
                available=available,
                reason=reason,
                effects=CapabilityEffects(),
                limitations=("Interface inference depends on the caller's evmole version.",),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format in ("file", "raw-binary", "unknown"):
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported", reason="EVM requires a raw/hex carrier", code="target_format_unsupported"
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del profile
        if operation != "inspect_evm_interface":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        available, reason = self._availability()
        if not available:
            return err(
                AnalysisCapabilityUnavailableError(
                    message=reason or "evmole is unavailable",
                    provider_id=_PROVIDER.id,
                    operation=operation,
                    reason="provider_unavailable",
                    remediation_action="Install the optional 'evmole' package and retry.",
                )
            )
        try:
            raw = Path(target.path).read_bytes()
        except OSError as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))

        carrier, code = _decode_carrier(raw)
        if code is None:
            return err(
                AnalysisInputError(
                    operation=operation, message="Carrier is not raw or hex bytecode"
                )
            )

        evmole = optional_import("evmole")
        assert evmole is not None
        try:
            functions = evmole.functions(code, result_arguments=True, result_state_mutability=True)
        except Exception as cause:
            return err(AnalysisInputError(operation=operation, message=f"evmole failed: {cause}"))

        selectors = [
            {
                "selector": function.get("selector")
                if isinstance(function.get("selector"), str)
                else f"0x{function.get('selector', 0):08x}",
                "arguments": function.get("arguments"),
                "state_mutability": function.get("state_mutability"),
            }
            for function in functions
        ]
        return ok(
            AnalysisExecution(
                result={
                    "carrier": carrier,
                    "bytecode_size": len(code),
                    "selector_count": len(selectors),
                    "selectors": selectors,
                },
                provider=_PROVIDER,
                limitations=(
                    "Selectors are inferred from bytecode; proxy and dynamic dispatch may be missed.",
                ),
            )
        )

    def _availability(self) -> tuple[bool, str | None]:
        if optional_import("evmole") is None:
            return False, "the optional 'evmole' package is not installed"
        return True, None


def _decode_carrier(raw: bytes) -> tuple[str, bytes | None]:
    stripped = raw.strip()
    if stripped[:2] in (b"0x", b"0X"):
        stripped = stripped[2:]
    if (
        stripped
        and all(byte in b"0123456789abcdefABCDEF" for byte in stripped)
        and len(stripped) % 2 == 0
    ):
        try:
            return "hex", bytes.fromhex(stripped.decode("ascii"))
        except ValueError:
            return "raw", raw
    return "raw", raw


__all__ = ["EvmInterfaceProvider"]
