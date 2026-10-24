"""Bounded desktop application directory triage."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .formats.pe import parse_pe
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(
    id="desktop-application", name="REA-Python desktop application", version="1"
)
_MAX_FILES = 5000


class DesktopApplicationProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="inspect_desktop_application",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=(
                    "Directory/file-marker triage only; binaries and packaged assets are not executed.",
                ),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.kind == "directory" or target.format == "directory" or Path(target.path).is_dir():
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported", reason="not a directory", code="target_format_unsupported"
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: Any,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del profile
        detail = str(parameters.get("detail") or "complete")
        if operation != "inspect_desktop_application":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        root = Path(target.path)
        try:
            files = [path for path in sorted(root.rglob("*")) if path.is_file()][:_MAX_FILES]
        except OSError as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        candidates: list[dict[str, Any]] = []
        components: list[dict[str, Any]] = []
        file_rows: list[dict[str, Any]] = []
        for path in files:
            relative_path = path.relative_to(root).as_posix()
            file_rows.append(
                {
                    "path": relative_path,
                    "size": path.stat().st_size,
                }
            )
            relative = path.relative_to(root).as_posix()
            lowered = relative.lower()
            kind = None
            if path.name == "global-metadata.dat":
                kind = "il2cpp-metadata"
            elif path.name.lower() in ("gameassembly.dll", "unityplayer.dll"):
                kind = "unity"
            elif lowered.endswith("resources/app.asar"):
                kind = "electron"
            elif lowered.endswith(".pck"):
                kind = "godot-pck"
            elif lowered.endswith(".pak"):
                kind = "unreal-pak"
            elif lowered.endswith("data.win"):
                kind = "gamemaker-data"
            elif lowered.endswith((".dll", ".exe")):
                try:
                    info = parse_pe(path.read_bytes()[: 1024 * 1024])
                except OSError:
                    info = None
                if info is not None and info.has_clr:
                    kind = "dotnet"
            if kind is None:
                continue
            candidate = {
                "path": relative,
                "kind": kind,
                "size": path.stat().st_size,
                "sha256": _sha256(path),
            }
            candidates.append(candidate)
            if kind in (
                "unity",
                "il2cpp-metadata",
                "electron",
                "godot-pck",
                "unreal-pak",
                "gamemaker-data",
            ):
                components.append({"kind": kind, "path": relative})
        return ok(
            AnalysisExecution(
                result={
                    "root": str(root),
                    "detail": detail,
                    "file_count": len(files),
                    "files": [] if detail == "summary" else file_rows,
                    "candidates": candidates,
                    "candidate_count": len(candidates),
                    "components": components,
                    "next_probes": _probes(candidates),
                    "coverage": {
                        "state": "complete" if len(files) < _MAX_FILES else "partial",
                        "issues": [],
                    },
                },
                provider=_PROVIDER,
                limitations=("Only file names, sizes and bounded headers are examined.",),
            )
        )


def _sha256(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _probes(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    probes = []
    kinds = {candidate["kind"] for candidate in candidates}
    if "dotnet" in kinds:
        probes.append({"operation": "inspect_managed_artifact", "reason": "managed PE candidate"})
    if "il2cpp-metadata" in kinds:
        probes.append({"operation": "inspect_il2cpp_metadata", "reason": "Unity IL2CPP metadata"})
    if "electron" in kinds:
        probes.append({"operation": "analyze_javascript_application", "reason": "Electron ASAR"})
    if "godot-pck" in kinds:
        probes.append({"operation": "inspect_artifact", "reason": "Godot PCK"})
    return probes


__all__ = ["DesktopApplicationProvider"]
