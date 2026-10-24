"""Pure-Python PE Authenticode certificate-table inspection."""

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
from .formats.pe import parse_pe
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="pe-certificates", name="REA-Python PE certificates", version="1")
_MAX_ENTRIES = 8


class PeCertificatesProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="inspect_pe_certificates",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=(
                    "WIN_CERTIFICATE entries are hashed; PKCS#7/X.509 fields and signature validity are not verified.",
                ),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format == "pe":
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported", reason="not a PE image", code="target_format_unsupported"
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del parameters, profile
        if operation != "inspect_pe_certificates":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        try:
            data = Path(target.path).read_bytes()
        except OSError as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        info = parse_pe(data)
        if info is None:
            return err(AnalysisInputError(operation=operation, message="Not a PE image"))
        table = _security_directory(data, info.is_pe32_plus)
        if table is None or table[1] == 0:
            return ok(
                AnalysisExecution(
                    result={"has_certificate_table": False, "table": None, "entries": []},
                    provider=_PROVIDER,
                    limitations=("No IMAGE_DIRECTORY_ENTRY_SECURITY table is present.",),
                )
            )
        offset, size = table
        if offset + size > len(data):
            return err(
                AnalysisInputError(
                    operation=operation,
                    message="PE security directory extends past the file",
                )
            )
        try:
            entries = _entries(data, offset, size)
        except (ValueError, struct.error) as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        return ok(
            AnalysisExecution(
                result={
                    "has_certificate_table": True,
                    "table": {"offset": offset, "size": size},
                    "entry_count": len(entries),
                    "entries": entries,
                },
                provider=_PROVIDER,
            )
        )


def _security_directory(data: bytes, is_plus: bool) -> tuple[int, int] | None:
    e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
    optional = e_lfanew + 24
    directory = optional + (112 if is_plus else 96) + 4 * 8
    if directory + 8 > len(data):
        return None
    offset, size = struct.unpack_from("<II", data, directory)
    return offset, size


def _entries(data: bytes, offset: int, size: int) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    cursor = offset
    end = offset + size
    while cursor + 8 <= end and len(entries) < _MAX_ENTRIES:
        length, revision, kind = struct.unpack_from("<IHH", data, cursor)
        if length < 8 or length > end - cursor:
            raise ValueError("truncated WIN_CERTIFICATE entry")
        payload = bytes(data[cursor + 8 : cursor + length])
        entries.append(
            {
                "length": length,
                "revision": revision,
                "type": kind,
                "payload_length": len(payload),
                "payload_sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
        cursor += (length + 7) & ~7
    return entries


__all__ = ["PeCertificatesProvider"]
