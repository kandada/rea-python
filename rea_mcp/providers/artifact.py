"""Built-in artifact inventory provider (zip, APK, ASAR, tar, directory, file)."""

from __future__ import annotations

import json
import struct
import tarfile
import zipfile
from pathlib import Path
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.digests import sha256_hex
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="artifacts", name="rea-mcp artifact inventory", version="1")
_SUPPORTED = {"zip", "apk", "asar", "directory", "file"}
_MAX_DIGEST_BYTES = 64 * 1024 * 1024
_MAX_ENTRIES = 20000
_DIGEST_BUDGET = 256 * 1024 * 1024


class _DigestBudget:
    """Bound total bytes hashed per inventory so a huge archive stays cheap."""

    def __init__(self, total: int = _DIGEST_BUDGET) -> None:
        self.remaining = total
        self.exhausted = False

    def allows(self, size: int) -> bool:
        if size > _MAX_DIGEST_BYTES or size > self.remaining:
            self.exhausted = True
            return False
        return True

    def take(self, size: int) -> None:
        self.remaining -= size


class ArtifactProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="inspect_artifact",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=("Archive members are listed; nested archives are not expanded.",),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format in _SUPPORTED or target.kind in ("directory", "archive", "package"):
            return TargetSupport("supported")
        return TargetSupport("supported")

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del profile
        if operation != "inspect_artifact":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        path = Path(target.path)
        try:
            if path.is_dir():
                result = _inventory_directory(path)
            elif target.format == "asar":
                result = _inventory_asar(path)
            elif target.format in ("zip", "apk") or zipfile.is_zipfile(path):
                result = _inventory_zip(path)
            elif tarfile.is_tarfile(path):
                result = _inventory_tar(path)
            else:
                result = _inventory_file(path)
        except OSError as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        except (zipfile.BadZipFile, tarfile.TarError, ValueError) as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))

        return ok(
            AnalysisExecution(result=_paginate_entries(result, parameters), provider=_PROVIDER)
        )


def _paginate_entries(result: dict[str, Any], parameters: dict[str, Any]) -> dict[str, Any]:
    entries = result.get("entries")
    if not isinstance(entries, list):
        return result
    offset = max(0, int(parameters.get("offset") or 0))
    limit = min(1000, max(1, int(parameters.get("limit") or 500)))
    total = len(entries)
    start = min(offset, total)
    page = entries[start : start + limit]
    result["entry_total"] = total
    result["entry_count"] = total
    result["entries_offset"] = start
    result["returned_entry_count"] = len(page)
    result["entries"] = page
    result["next_offset"] = start + len(page) if start + len(page) < total else None
    return result


def _entry(name: str, size: int, digest: str | None = None) -> dict[str, Any]:
    entry: dict[str, Any] = {"path": name, "size": size}
    if digest is not None:
        entry["sha256"] = digest
    return entry


def _inventory_zip(path: Path) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    budget = _DigestBudget()
    with zipfile.ZipFile(path) as archive:
        infos = sorted(archive.infolist(), key=lambda info: info.filename)
        truncated = len(infos) > _MAX_ENTRIES
        for info in infos[:_MAX_ENTRIES]:
            if info.is_dir():
                continue
            digest: str | None = None
            if budget.allows(info.file_size):
                digest = sha256_hex(archive.read(info.filename))
                budget.take(info.file_size)
            entries.append(_entry(info.filename, info.file_size, digest))
    return {
        "format": "zip",
        "entries": entries,
        "entry_count": len(entries),
        "truncated": truncated,
        "digests_truncated": budget.exhausted,
    }


def _inventory_tar(path: Path) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    budget = _DigestBudget()
    with tarfile.open(path) as archive:
        members = sorted(archive.getmembers(), key=lambda member: member.name)
        for member in members[:_MAX_ENTRIES]:
            if not member.isfile():
                continue
            digest: str | None = None
            if member.size >= 0 and budget.allows(member.size):
                extracted = archive.extractfile(member)
                if extracted is not None:
                    digest = sha256_hex(extracted.read())
                    budget.take(member.size)
            entries.append(_entry(member.name, member.size, digest))
    return {
        "format": "tar",
        "entries": entries,
        "entry_count": len(entries),
        "digests_truncated": budget.exhausted,
    }


def _inventory_directory(path: Path) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    budget = _DigestBudget()
    for child in sorted(path.rglob("*")):
        if not child.is_file():
            continue
        rel = child.relative_to(path).as_posix()
        size = child.stat().st_size
        digest: str | None = None
        if budget.allows(size):
            digest = sha256_hex(child.read_bytes())
            budget.take(size)
        entries.append(_entry(rel, size, digest))
        if len(entries) >= _MAX_ENTRIES:
            break
    return {
        "format": "directory",
        "entries": entries,
        "entry_count": len(entries),
        "truncated": len(entries) >= _MAX_ENTRIES,
        "digests_truncated": budget.exhausted,
    }


def _is_dmg(path: Path) -> bool:
    try:
        if path.stat().st_size < 512:
            return False
        with path.open("rb") as handle:
            handle.seek(-512, 2)
            return handle.read(4) == b"koly"
    except OSError:
        return False


def _inventory_dmg(path: Path) -> dict[str, Any]:
    size = path.stat().st_size
    with path.open("rb") as handle:
        handle.seek(size - 512)
        trailer = handle.read(512)
    digest = sha256_hex(path.read_bytes()) if size <= _MAX_DIGEST_BYTES else None
    return {
        "format": "dmg",
        "entries": [_entry(path.name, size, digest)],
        "entry_count": 1,
        "dmg": {
            "version": struct.unpack(">I", trailer[4:8])[0],
            "data_fork_offset": struct.unpack(">Q", trailer[24:32])[0],
            "data_fork_length": struct.unpack(">Q", trailer[32:40])[0],
            "xml_offset": struct.unpack(">Q", trailer[216:224])[0],
            "xml_length": struct.unpack(">Q", trailer[224:232])[0],
            "sector_count": struct.unpack(">Q", trailer[492:500])[0],
        },
    }


def _inventory_file(path: Path) -> dict[str, Any]:
    if path.suffix.lower() == ".dmg" or _is_dmg(path):
        return _inventory_dmg(path)
    size = path.stat().st_size
    digest = sha256_hex(path.read_bytes()) if size <= _MAX_DIGEST_BYTES else None
    return {"format": "file", "entries": [_entry(path.name, size, digest)], "entry_count": 1}


def _inventory_asar(path: Path) -> dict[str, Any]:
    with open(path, "rb") as handle:
        prefix = handle.read(16)
    if len(prefix) < 16:
        raise ValueError("ASAR header is truncated")
    header_size = struct.unpack_from("<I", prefix, 4)[0]
    json_size = struct.unpack_from("<I", prefix, 8)[0]
    with open(path, "rb") as handle:
        handle.seek(12)
        raw = handle.read(json_size)
    header = json.loads(raw.decode("utf-8"))
    entries: list[dict[str, Any]] = []
    _walk_asar(header.get("files", {}), "", entries)
    entries.sort(key=lambda entry: entry["path"])
    return {
        "format": "asar",
        "header_size": header_size,
        "entries": entries,
        "entry_count": len(entries),
    }


def _walk_asar(node: Any, prefix: str, entries: list[dict[str, Any]]) -> None:
    if not isinstance(node, dict):
        return
    for name, child in node.items():
        path = f"{prefix}/{name}" if prefix else name
        if isinstance(child, dict) and "files" in child:
            _walk_asar(child["files"], path, entries)
        elif isinstance(child, dict):
            size = int(child.get("size", 0))
            entry = _entry(path, size)
            if "unpacked" in child:
                entry["unpacked"] = bool(child["unpacked"])
            entries.append(entry)


__all__ = ["ArtifactProvider"]
