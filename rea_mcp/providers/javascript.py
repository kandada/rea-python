"""JavaScript/Electron static application graph provider.

Builds a module graph from an extracted app directory or an ASAR archive by
extracting ``require``/``import`` edges. Electron boundaries (main/preload/
renderer, ipcMain/ipcRenderer) are detected by filename and token presence. A
bounded, regex-based extractor is used; this is structural, not a full parser.
"""

from __future__ import annotations

import json
import re
import struct
from pathlib import Path
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(
    id="javascript", name="REA-Python JavaScript application graph", version="1"
)

_IMPORT_RE = re.compile(
    r"""(?:require\s*\(\s*|from\s+|import\s*\(\s*)["']([^"']+)["']""",
)
_JS_SUFFIXES = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")
_MAX_FILES = 500
_MAX_FILE_BYTES = 512 * 1024


class JavaScriptApplicationProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="analyze_javascript_application",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=(
                    "Edges come from a bounded regex extractor; dynamic requires may be missed.",
                ),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format in ("asar", "directory") or target.kind == "directory":
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported", reason="not a JS app directory or ASAR", code="target_format_unsupported"
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del parameters, profile
        if operation != "analyze_javascript_application":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        path = Path(target.path)
        asar_integrity: dict[str, Any] | None = None
        try:
            if target.format == "asar" or path.suffix == ".asar":
                sources, asar_integrity = _read_asar_sources(path)
            else:
                sources = _read_directory_sources(path)
        except OSError as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))

        modules: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, str]] = []
        electron_flags: set[str] = set()
        for name, text in sources.items():
            imports = sorted(set(_IMPORT_RE.findall(text)))
            modules[name] = {"imports": imports, "size": len(text)}
            for spec in imports:
                edges.append({"from": name, "to": spec})
            lowered = name.lower()
            if "preload" in lowered:
                electron_flags.add("preload")
            elif "main" in lowered:
                electron_flags.add("main")
            elif "renderer" in lowered:
                electron_flags.add("renderer")
            if "ipcMain" in text:
                electron_flags.add("ipcMain")
            if "ipcRenderer" in text:
                electron_flags.add("ipcRenderer")

        result: dict[str, Any] = {
            "module_count": len(modules),
            "modules": modules,
            "edge_count": len(edges),
            "edges": edges[:2000],
            "electron": {
                "is_electron": bool(
                    {"main", "preload", "renderer", "ipcMain", "ipcRenderer"} & electron_flags
                ),
                "roles": sorted(electron_flags),
            },
        }
        if asar_integrity is not None:
            result["asar_integrity"] = asar_integrity
        return ok(
            AnalysisExecution(
                result=result,
                provider=_PROVIDER,
                limitations=("Graph edges are specifier strings, not resolved module identities.",),
            )
        )


def _read_directory_sources(root: Path) -> dict[str, str]:
    sources: dict[str, str] = {}
    for child in sorted(root.rglob("*")):
        if not child.is_file() or child.suffix.lower() not in _JS_SUFFIXES:
            continue
        if "node_modules" in child.parts:
            continue
        if len(sources) >= _MAX_FILES:
            break
        sources[child.relative_to(root).as_posix()] = _read_text(child)
    return sources


def _read_asar_sources(path: Path) -> tuple[dict[str, str], dict[str, Any]]:
    with open(path, "rb") as handle:
        prefix = handle.read(16)
        if len(prefix) < 16:
            raise OSError("ASAR header is truncated")
        header_size = struct.unpack_from("<I", prefix, 4)[0]
        json_size = struct.unpack_from("<I", prefix, 8)[0]
        handle.seek(12)
        raw = handle.read(json_size)
        parsed = json.loads(raw.decode("utf-8"))
        data_start = 8 + header_size
        entries: list[tuple[str, int, int]] = []
        _collect_asar_files(parsed.get("files", {}), "", entries)
        sources: dict[str, str] = {}
        for rel, offset, size in entries[:_MAX_FILES]:
            handle.seek(data_start + offset)
            sources[rel] = handle.read(min(size, _MAX_FILE_BYTES)).decode("utf-8", errors="replace")
        integrity_entries: list[dict[str, Any]] = []
        _collect_asar_integrity(parsed.get("files", {}), "", integrity_entries)
    summary = {
        "entry_count": len(integrity_entries),
        "algorithms": sorted(
            {str(item["algorithm"]) for item in integrity_entries if item.get("algorithm")}
        ),
        "entries": integrity_entries[:200],
    }
    return sources, summary


def _collect_asar_integrity(node: Any, prefix: str, out: list[dict[str, Any]]) -> None:
    if not isinstance(node, dict):
        return
    for name, child in node.items():
        if not isinstance(child, dict):
            continue
        rel = f"{prefix}/{name}" if prefix else name
        if isinstance(child.get("files"), dict):
            _collect_asar_integrity(child["files"], rel, out)
            continue
        integrity = child.get("integrity")
        if isinstance(integrity, dict):
            out.append(
                {
                    "path": rel,
                    "algorithm": integrity.get("algorithm"),
                    "hash": integrity.get("hash"),
                    "block_size": integrity.get("blockSize"),
                    "block_count": len(integrity.get("blocks") or []),
                }
            )


def _collect_asar_files(node: Any, prefix: str, out: list[tuple[str, int, int]]) -> None:
    if not isinstance(node, dict):
        return
    for name, child in node.items():
        rel = f"{prefix}/{name}" if prefix else name
        if isinstance(child, dict) and "files" in child:
            _collect_asar_files(child["files"], rel, out)
        elif isinstance(child, dict) and rel.endswith(_JS_SUFFIXES) and "offset" in child:
            out.append((rel, int(child.get("offset", 0)), int(child.get("size", 0))))


def _read_text(path: Path) -> str:
    try:
        data = path.read_bytes()[:_MAX_FILE_BYTES]
    except OSError:
        return ""
    return data.decode("utf-8", errors="replace")


__all__ = ["JavaScriptApplicationProvider"]
