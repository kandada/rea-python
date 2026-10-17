"""Built-in Flutter build identification provider.

Detects Flutter applications statically from an APK by locating per-ABI
``libapp.so`` Dart AOT snapshot images and reading the snapshot fingerprint. No
Flutter engine or device is required.
"""

from __future__ import annotations

import zipfile
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.digests import sha256_hex
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="flutter", name="REA-Python Flutter identification", version="1")

# Dart VM snapshot magic variants (little/big-endian readings of 0xf5f5dcd0).
_SNAPSHOT_MAGICS = (b"\xf5\xf5\xdc\xd0", b"\xd0\xdc\xf5\xf5")
_SNAPSHOT_HASH_LENGTH = 16
_SCAN_BYTES = 512


class FlutterBuildProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="identify_flutter_build",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=(
                    "Static snapshot fingerprint only; class/URI recovery is out of scope.",
                ),
            ),
            CapabilityDescriptor(
                operation="inspect_dart_aot",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=("Static AOT snapshot facts only; no Dart class recovery.",),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format == "apk":
            return TargetSupport("supported")
        return TargetSupport("unsupported", reason="not an APK", code="target_format_unsupported")

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del parameters, profile
        if operation not in ("identify_flutter_build", "inspect_dart_aot"):
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        try:
            with zipfile.ZipFile(target.path) as archive:
                libapp_entries = sorted(
                    name
                    for name in archive.namelist()
                    if name.startswith("lib/") and name.endswith("/libapp.so")
                )
                abis: dict[str, dict[str, Any]] = {}
                for name in libapp_entries:
                    abi = name.split("/")[1] if name.count("/") >= 2 else name
                    with archive.open(name) as handle:
                        data = handle.read()
                    abis[abi] = {
                        "path": name,
                        "sha256": sha256_hex(data),
                        "size": len(data),
                        "snapshot_hash": _snapshot_hash(data),
                        "package_uri_count": data.count(b"package:"),
                        "dart_uri_count": data.count(b"dart:"),
                    }
        except zipfile.BadZipFile as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        except OSError as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))

        detected = bool(abis)
        hashes = {facts["snapshot_hash"] for facts in abis.values() if facts["snapshot_hash"]}
        return ok(
            AnalysisExecution(
                result={
                    "is_flutter": detected,
                    "is_dart_aot": detected,
                    "abis": abis,
                    "consistent_snapshot": len(hashes) == 1 if hashes else False,
                    "snapshot_hashes": sorted(hashes),
                },
                provider=_PROVIDER,
                limitations=(
                    "A missing libapp.so means not-detected for this static check; "
                    "it is not proof the app is not Flutter.",
                ),
            )
        )


def _snapshot_hash(data: bytes) -> str | None:
    window = data[:_SCAN_BYTES]
    for magic in _SNAPSHOT_MAGICS:
        index = window.find(magic)
        if index != -1:
            start = index + len(magic)
            chunk = data[start : start + _SNAPSHOT_HASH_LENGTH]
            if len(chunk) == _SNAPSHOT_HASH_LENGTH:
                return chunk.hex()
    return None


__all__ = ["FlutterBuildProvider"]
