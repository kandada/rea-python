"""Apple property-list based providers: NSKeyedArchiver archives."""

from __future__ import annotations

import plistlib
from pathlib import Path
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="apple", name="REA-Python Apple archives", version="1")


class KeyedArchiveProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="inspect_keyed_archive",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=(
                    "Class and object inventory only; the object graph is not reconstructed.",
                ),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format == "plist":
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported", reason="not a property list archive", code="target_format_unsupported"
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del parameters, profile
        if operation != "inspect_keyed_archive":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        try:
            with open(target.path, "rb") as handle:
                parsed = plistlib.loads(handle.read())
        except (plistlib.InvalidFileException, ValueError, OSError) as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))

        if not isinstance(parsed, dict) or "$objects" not in parsed:
            return ok(
                AnalysisExecution(
                    result={"is_keyed_archive": False},
                    provider=_PROVIDER,
                    limitations=("Not an NSKeyedArchiver archive.",),
                )
            )
        objects = parsed.get("$objects", [])
        class_names = sorted(
            {
                obj["$classname"]
                for obj in objects
                if isinstance(obj, dict) and isinstance(obj.get("$classname"), str)
            }
        )
        return ok(
            AnalysisExecution(
                result={
                    "is_keyed_archive": True,
                    "archiver": parsed.get("$archiver"),
                    "object_count": len(objects),
                    "class_names": class_names,
                    "top_level_keys": list(parsed.get("$top", {}).keys())
                    if isinstance(parsed.get("$top"), dict)
                    else [],
                },
                provider=_PROVIDER,
                limitations=("Class inventory only; decoded object values are not returned.",),
            )
        )


class AssetCatalogProvider(AnalysisProvider):
    _IDENTITY = ProviderIdentity(id="asset-catalog", name="REA-Python asset catalogs", version="1")

    def identity(self) -> ProviderIdentity:
        return self._IDENTITY

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="inspect_asset_catalog",
                provider=self._IDENTITY,
                effects=CapabilityEffects(),
                limitations=(
                    "Header and embedded strings only; rendition decoding is not implemented.",
                ),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format in ("file", "unknown"):
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported",
            reason="asset catalog requires a raw file",
            code="target_format_unsupported",
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del profile, parameters
        if operation != "inspect_asset_catalog":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        try:
            data = Path(target.path).read_bytes()
        except OSError as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        if data[:4] != b"CORE":
            return ok(
                AnalysisExecution(
                    result={"is_asset_catalog": False},
                    provider=self._IDENTITY,
                    limitations=("Not an Apple asset catalog (missing CORE magic).",),
                )
            )
        strings = _embedded_strings(data)
        return ok(
            AnalysisExecution(
                result={
                    "is_asset_catalog": True,
                    "version": int.from_bytes(data[4:8], "big"),
                    "size": len(data),
                    "string_count": len(strings),
                    "strings": strings[:200],
                },
                provider=self._IDENTITY,
                limitations=("Rendition names and image data are not decoded.",),
            )
        )


def _embedded_strings(data: bytes, minimum: int = 4) -> list[str]:
    result: list[str] = []
    current = bytearray()
    for byte in data:
        if 0x20 <= byte < 0x7F:
            current.append(byte)
        else:
            if len(current) >= minimum:
                result.append(current.decode("ascii", errors="replace"))
                if len(result) >= 2000:
                    break
            current.clear()
    if len(current) >= minimum:
        result.append(current.decode("ascii", errors="replace"))
    return result


class EntitlementsProvider(AnalysisProvider):
    _IDENTITY = ProviderIdentity(id="entitlements", name="rea-mcp entitlements", version="1")

    def identity(self) -> ProviderIdentity:
        return self._IDENTITY

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="inspect_entitlements",
                provider=self._IDENTITY,
                effects=CapabilityEffects(),
                limitations=("Entitlement values are returned verbatim from the plist.",),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format == "plist":
            return TargetSupport("supported")
        return TargetSupport("unsupported", reason="not a plist", code="target_format_unsupported")

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del profile, parameters
        if operation != "inspect_entitlements":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        try:
            with open(target.path, "rb") as handle:
                parsed = plistlib.loads(handle.read())
        except (plistlib.InvalidFileException, ValueError, OSError) as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        if not isinstance(parsed, dict):
            return ok(
                AnalysisExecution(
                    result={"is_entitlements": False, "entitlements": {}},
                    provider=self._IDENTITY,
                    limitations=("Not an entitlements dictionary.",),
                )
            )
        entitlements = {str(key): value for key, value in parsed.items()}
        return ok(
            AnalysisExecution(
                result={
                    "is_entitlements": True,
                    "entitlement_count": len(entitlements),
                    "entitlements": entitlements,
                },
                provider=self._IDENTITY,
            )
        )


class InterfaceBuilderProvider(AnalysisProvider):
    """Project a compiled Interface Builder archive (.nib/.storyboardc)."""

    _IDENTITY = ProviderIdentity(
        id="interface-builder", name="rea-mcp Interface Builder", version="1"
    )

    def identity(self) -> ProviderIdentity:
        return self._IDENTITY

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="inspect_interface_builder",
                provider=self._IDENTITY,
                effects=CapabilityEffects(),
                limitations=(
                    "Object/class inventory only; the view hierarchy is not reconstructed.",
                ),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format == "plist":
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported", reason="not a nib/keyed archive", code="target_format_unsupported"
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del profile, parameters
        if operation != "inspect_interface_builder":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        try:
            with open(target.path, "rb") as handle:
                parsed = plistlib.loads(handle.read())
        except (plistlib.InvalidFileException, ValueError, OSError) as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        objects = parsed.get("$objects", []) if isinstance(parsed, dict) else []
        if not isinstance(objects, list) or not any(
            isinstance(obj, dict) and "$classname" in obj for obj in objects
        ):
            return ok(
                AnalysisExecution(
                    result={"is_interface_builder": False},
                    provider=self._IDENTITY,
                    limitations=("Not an Interface Builder keyed archive.",),
                )
            )
        class_names = sorted(
            {
                obj["$classname"]
                for obj in objects
                if isinstance(obj, dict) and isinstance(obj.get("$classname"), str)
            }
        )
        return ok(
            AnalysisExecution(
                result={
                    "is_interface_builder": True,
                    "object_count": len(objects),
                    "class_names": class_names,
                },
                provider=self._IDENTITY,
            )
        )


__all__ = [
    "AssetCatalogProvider",
    "EntitlementsProvider",
    "InterfaceBuilderProvider",
    "KeyedArchiveProvider",
]
