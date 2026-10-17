"""Built-in Rust binary provider (``cargo-auditable`` dependency inventory).

Reads the embedded ``.dep-v0`` section (zlib-compressed JSON) from ELF/PE images
without a Rust toolchain. A missing section means "no auditable metadata", not
"no dependencies".
"""

from __future__ import annotations

import json
import mmap
import zlib
from pathlib import Path
from typing import Any, cast

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .formats.elf import parse_elf
from .formats.pe import parse_pe
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="rust", name="REA-Python Rust metadata", version="1")
_SECTION = ".dep-v0"


class RustBinaryProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="inspect_rust_binary",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=(
                    "A missing .dep-v0 section is null metadata, not proof of no dependencies.",
                ),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format in ("elf", "pe"):
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported",
            reason="cargo-auditable requires ELF/PE",
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
        if operation != "inspect_rust_binary":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        try:
            data = Path(target.path).read_bytes()
        except OSError as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))

        section = _extract_section(data, target.format)
        if section is None:
            return ok(
                AnalysisExecution(
                    result={
                        "has_dependency_metadata": False,
                        "packages": [],
                        "root_package": None,
                    },
                    provider=_PROVIDER,
                    limitations=("No .dep-v0 section was found in this image.",),
                )
            )

        payload = _decode(section)
        if payload is None:
            return err(
                AnalysisInputError(
                    operation=operation,
                    message="The .dep-v0 section is present but could not be decoded",
                )
            )
        packages, root, edges = _project(payload)
        return ok(
            AnalysisExecution(
                result={
                    "has_dependency_metadata": True,
                    "packages": packages,
                    "root_package": root,
                    "package_count": len(packages),
                    "dependency_edges": edges,
                },
                provider=_PROVIDER,
            )
        )


def _extract_section(data: bytes | mmap.mmap, target_format: str) -> bytes | None:
    if target_format == "elf":
        elf = parse_elf(data)
        if elf is None:
            return None
        for section in elf.sections:
            if section.name == _SECTION:
                return data[section.offset : section.offset + section.size]
        return None
    if target_format == "pe":
        pe = parse_pe(data)
        if pe is None:
            return None
        for pe_section in pe.sections:
            if pe_section.name == _SECTION:
                start = pe_section.pointer_to_raw_data
                return data[start : start + pe_section.size_of_raw_data]
        return None
    return None


def _decode(section: bytes) -> dict[str, Any] | None:
    raw: bytes | None = None
    try:
        raw = zlib.decompress(section)
    except zlib.error:
        raw = None
    if raw is None:
        stripped = section.lstrip(b"\x00")
        try:
            raw = zlib.decompress(stripped)
        except zlib.error:
            try:
                inline = json.loads(section.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return None
            return cast(dict[str, Any], inline) if isinstance(inline, dict) else None
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return cast(dict[str, Any], decoded) if isinstance(decoded, dict) else None


def _project(
    payload: dict[str, Any],
) -> tuple[list[dict[str, str]], dict[str, str] | None, list[dict[str, str]]]:
    raw_packages = payload.get("packages", [])
    named: dict[int, dict[str, str]] = {}
    if isinstance(raw_packages, list):
        for index, entry in enumerate(raw_packages):
            if isinstance(entry, dict):
                named[index] = {
                    "name": str(entry.get("name", "")),
                    "version": str(entry.get("version", "")),
                    "source": str(entry.get("source", "")),
                }
    edges: list[dict[str, str]] = []
    if isinstance(raw_packages, list):
        for index, entry in enumerate(raw_packages):
            if not isinstance(entry, dict):
                continue
            for dep in entry.get("dependencies", []) or []:
                dep_index = dep.get("index") if isinstance(dep, dict) else dep
                if isinstance(dep_index, int) and dep_index in named and index in named:
                    edges.append({"from": named[index]["name"], "to": named[dep_index]["name"]})
    packages = sorted(named.values(), key=lambda package: (package["name"], package["version"]))
    root_index = payload.get("root")
    root = named.get(root_index) if isinstance(root_index, int) else None
    return packages, root, edges


__all__ = ["RustBinaryProvider"]
