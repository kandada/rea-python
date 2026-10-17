"""HarmonyOS HAP package provider (zip + Stage-model JSON)."""

from __future__ import annotations

import json
import zipfile
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.digests import sha256_hex
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="harmony", name="REA-Python HarmonyOS packages", version="1")


class HarmonyProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="inspect_harmony_package",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=("Stage-model JSON only; .abc bytecode is inventoried, not decoded.",),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format == "hap":
            return TargetSupport("supported")
        return TargetSupport("unsupported", reason="not a HAP", code="target_format_unsupported")

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del parameters, profile
        if operation != "inspect_harmony_package":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        try:
            with zipfile.ZipFile(target.path) as archive:
                names = sorted(archive.namelist())
                module = _read_json(archive, "module.json") or _read_json(archive, "pack.info")
                abc_files = [n for n in names if n.endswith(".abc")]
                so_files = [n for n in names if n.endswith(".so")]
                entry_hashes = {
                    name: sha256_hex(archive.read(name))
                    for name in names
                    if name.endswith((".abc", ".so"))
                }
        except (zipfile.BadZipFile, OSError) as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))

        app = (module or {}).get("app", {})
        module_info = (module or {}).get("module", {})
        return ok(
            AnalysisExecution(
                result={
                    "bundle_name": app.get("bundleName"),
                    "version_name": app.get("versionName", module_info.get("versionName")),
                    "version_code": app.get("versionCode", module_info.get("versionCode")),
                    "module_name": module_info.get("name"),
                    "entry_count": len(names),
                    "abc_files": abc_files,
                    "native_libraries": so_files,
                    "entry_hashes": entry_hashes,
                    "manifest_decoded": module is not None,
                },
                provider=_PROVIDER,
                limitations=(".abc bytecode semantics are not decoded.",),
            )
        )


def _read_json(archive: zipfile.ZipFile, name: str) -> dict[str, Any] | None:
    try:
        raw = archive.read(name)
    except KeyError:
        return None
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


__all__ = ["HarmonyProvider"]
