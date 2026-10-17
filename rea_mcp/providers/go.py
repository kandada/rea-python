"""Built-in Go binary metadata provider.

Extracts the embedded Go build info (compiler version, module list, build
settings) from ELF/PE/Mach-O images without a Go toolchain. The module table is
recovered from the embedded ``runtime.modinfo`` text; the header is only read to
confirm a Go image and locate the version token.
"""

from __future__ import annotations

import mmap
import re
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .formats.io import open_target
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="go", name="REA-Python Go metadata", version="1")
_MAGIC = b"\xff Go buildinf:"
_GO_VERSION_RE = re.compile(rb"go1\.\d+(?:\.\d+)?(?:rc\d+|beta\d+)?")
_MODULE_PREFIXES = (b"path\t", b"mod\t", b"dep\t", b"build\t", b"=>\t")


class GoBinaryProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="inspect_go_binary",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=("Module table is recovered heuristically from embedded text.",),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format in ("elf", "pe", "mach-o"):
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported",
            reason="Go metadata requires ELF/PE/Mach-O",
            code="target_format_unsupported",
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del parameters, profile
        if operation != "inspect_go_binary":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        index = -1
        ptr_size = 0
        flags = 0
        version: str | None = None
        modules: list[dict[str, str]] = []
        main_module: dict[str, str] | None = None
        settings: dict[str, str] = {}
        replacements: list[dict[str, str]] = []
        try:
            with open_target(target.path) as data:
                index = data.find(_MAGIC)
                if index != -1:
                    ptr_size = data[index + 14] if index + 15 < len(data) else 0
                    flags = data[index + 15] if index + 16 < len(data) else 0
                    version = _find_version(data, index)
                    modules, main_module, settings, replacements = _parse_modules(data, index)
        except OSError as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))

        if index == -1:
            return ok(
                AnalysisExecution(
                    result={
                        "is_go": False,
                        "compiler_version": None,
                        "modules": [],
                        "build_settings": {},
                    },
                    provider=_PROVIDER,
                    limitations=(
                        "No Go build info magic was found; the image is not a Go binary.",
                    ),
                )
            )

        return ok(
            AnalysisExecution(
                result={
                    "is_go": True,
                    "pointer_size": ptr_size if ptr_size in (4, 8) else None,
                    "endianness": "little" if flags & 1 == 0 else "big",
                    "compiler_version": version,
                    "main_module": main_module,
                    "modules": modules,
                    "build_settings": settings,
                    "replacements": replacements,
                    "buildinfo_offset": index,
                },
                provider=_PROVIDER,
                limitations=(
                    "Module inventory is recovered from embedded text and may omit entries.",
                ),
            )
        )


def _find_version(data: bytes | mmap.mmap, index: int) -> str | None:
    window = data[index : index + 256]
    match = _GO_VERSION_RE.search(window)
    return match.group(0).decode("ascii") if match else None


def _parse_modules(
    data: bytes | mmap.mmap, index: int
) -> tuple[list[dict[str, str]], dict[str, str] | None, dict[str, str], list[dict[str, str]]]:
    start = data.find(b"\npath\t", index)
    if start == -1:
        start = data.find(b"path\t", index)
        if start == -1:
            return [], None, {}, []
    else:
        start += 1

    end = start
    while end < len(data) and (data[end] not in (0x00, 0xFF)):
        end += 1
    blob = data[start:end]

    modules: list[dict[str, str]] = []
    settings: dict[str, str] = {}
    replacements: list[dict[str, str]] = []
    main_module: dict[str, str] | None = None
    for raw_line in blob.split(b"\n"):
        if not raw_line or not any(raw_line.startswith(prefix) for prefix in _MODULE_PREFIXES):
            continue
        try:
            parts = raw_line.split(b"\t")
            kind = parts[0].decode("ascii", errors="replace")
        except Exception:  # pragma: no cover - defensive
            continue
        fields = [part.decode("utf-8", errors="replace") for part in parts[1:] if part != b""]
        if kind == "path" and fields:
            main_module = {"path": fields[0]}
        elif kind == "mod" and len(fields) >= 2:
            main_module = {"path": fields[0], "version": fields[1]}
        elif kind == "dep" and len(fields) >= 2:
            modules.append({"path": fields[0], "version": fields[1]})
        elif kind == "build" and len(fields) >= 2:
            settings[fields[0]] = fields[1]
        elif kind == "=>" and fields:
            replacements.append({"replacement": " ".join(fields)})
    modules.sort(key=lambda module: module["path"])
    return modules, main_module, settings, replacements


__all__ = ["GoBinaryProvider"]
