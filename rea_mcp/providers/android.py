"""Built-in Android APK static provider.

Reads the APK as a zip, inventories entries, counts DEX files, and decodes
manifest-level facts from the binary AndroidManifest.xml. The app is never
installed or executed.
"""

from __future__ import annotations

import zipfile
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .formats.axml import AxmlError, parse_axml
from .paging import page_sequence
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="android", name="REA-Python Android static", version="1")


class AndroidProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="inspect_android_package",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=("Static APK parsing only; no device and no execution.",),
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
        del profile
        if operation != "inspect_android_package":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        try:
            with zipfile.ZipFile(target.path) as archive:
                names = sorted(archive.namelist())
                dex_files = [name for name in names if name.endswith(".dex")]
                dex_versions = _dex_versions(archive, dex_files)
                manifest = _manifest(archive)
        except zipfile.BadZipFile as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        except OSError as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))

        has_native = any(name.endswith(".so") for name in names)
        offset = int(parameters.get("offset") or 0)
        limit = int(parameters.get("limit") or 200)
        permissions = manifest.get("permissions", []) if manifest else []
        permission_page = page_sequence(permissions, offset=offset, limit=limit)
        native_libraries = [name for name in names if name.endswith(".so")]
        native_page = page_sequence(native_libraries, offset=offset, limit=limit)
        raw_components = manifest.get("components", {}) if manifest else {}
        components: dict[str, Any] = {}
        component_totals: dict[str, int] = {}
        component_next_offsets: dict[str, int | None] = {}
        for key, value in raw_components.items():
            if isinstance(value, list):
                page = page_sequence(value, offset=offset, limit=limit)
                components[key] = page["items"]
                component_totals[key] = page["total"]
                component_next_offsets[key] = page["next_offset"]
            else:
                components[key] = value
        return ok(
            AnalysisExecution(
                result={
                    "package": manifest.get("package") if manifest else None,
                    "version_name": manifest.get("version_name") if manifest else None,
                    "version_code": manifest.get("version_code") if manifest else None,
                    "entry_count": len(names),
                    "dex_files": dex_files,
                    "dex_versions": dex_versions,
                    "has_native_libraries": has_native,
                    "native_libraries": native_page["items"],
                    "native_libraries_total": native_page["total"],
                    "native_libraries_offset": native_page["offset"],
                    "native_libraries_next_offset": native_page["next_offset"],
                    "manifest_decoded": manifest is not None,
                    "permissions": permission_page["items"],
                    "permissions_total": permission_page["total"],
                    "permissions_offset": permission_page["offset"],
                    "permissions_next_offset": permission_page["next_offset"],
                    "components": components,
                    "component_totals": component_totals,
                    "component_next_offsets": component_next_offsets,
                    "application": manifest.get("application", {}) if manifest else {},
                },
                provider=_PROVIDER,
                limitations=(
                    "DEX class bodies and resources are not decoded; manifest components are static.",
                ),
            )
        )


def _dex_versions(archive: zipfile.ZipFile, dex_files: list[str]) -> dict[str, str | None]:
    versions: dict[str, str | None] = {}
    for name in dex_files:
        with archive.open(name) as handle:
            magic = handle.read(8)
        if magic.startswith(b"dex\n") and magic.endswith(b"\x00"):
            versions[name] = magic[4:7].decode("ascii", errors="replace")
        else:
            versions[name] = None
    return versions


def _manifest(archive: zipfile.ZipFile) -> dict[str, Any] | None:
    try:
        raw = archive.read("AndroidManifest.xml")
    except KeyError:
        return None
    try:
        parsed = parse_axml(raw)
    except AxmlError:
        return None
    return parsed.get("manifest")


__all__ = ["AndroidProvider"]
