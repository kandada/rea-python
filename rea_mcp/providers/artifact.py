"""Built-in artifact inventory provider (zip, APK, ASAR, tar, directory, file)."""

from __future__ import annotations

import hashlib
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
            elif path.suffix.lower() == ".pck" or path.read_bytes()[:4] == b"GDPC":
                result = _inventory_pck(path)
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


def _inventory_pck(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    if len(data) < 40 or data[:4] != b"GDPC":
        raise ValueError("Not a Godot PCK")
    version = struct.unpack_from("<I", data, 4)[0]
    if version not in (2, 3, 4):
        raise ValueError(f"Unsupported Godot PCK version {version}")
    flags = struct.unpack_from("<I", data, 20)[0]
    file_base = struct.unpack_from("<Q", data, 24)[0]
    directory = struct.unpack_from("<Q", data, 32)[0] if version >= 3 else 96
    if directory + 4 > len(data):
        raise ValueError("Godot PCK directory is outside the file")
    count = struct.unpack_from("<I", data, directory)[0]
    directory_status = "encrypted" if flags & 1 else "sparse-bundle" if flags & 4 else "available"
    if directory_status != "available":
        return {
            "format": "godot-pck",
            "pck": {
                "format_version": version,
                "engine_major": struct.unpack_from("<I", data, 8)[0],
                "engine_minor": struct.unpack_from("<I", data, 12)[0],
                "engine_patch": struct.unpack_from("<I", data, 16)[0],
                "flags": flags,
                "file_base": file_base,
                "directory_start": directory,
                "declared_file_count": count,
                "directory_status": directory_status,
            },
            "entries": [],
            "entry_count": 0,
            "entry_total": count,
            "returned_entry_count": 0,
            "next_offset": None,
            "limitations": [
                "Godot PCK directory is encrypted; member identities and contents remain unknown."
                if directory_status == "encrypted"
                else "Godot PCK is a sparse bundle; external member bytes were not traversed."
            ],
        }
    cursor = directory + 4
    entries: list[dict[str, Any]] = []
    declared_plaintext = 0
    expansion_budget = max(256 * 1024 * 1024, 500 * len(data))
    for _index in range(min(count, _MAX_ENTRIES)):
        if cursor + 4 > len(data):
            raise ValueError("truncated Godot PCK entry")
        path_len = struct.unpack_from("<I", data, cursor)[0]
        cursor += 4
        if cursor + path_len + 8 + 8 + 16 + 4 > len(data):
            raise ValueError("truncated Godot PCK entry")
        raw_path = data[cursor : cursor + path_len]
        cursor += path_len
        offset, size = struct.unpack_from("<QQ", data, cursor)
        cursor += 16
        md5 = data[cursor : cursor + 16]
        cursor += 16
        entry_flags = struct.unpack_from("<I", data, cursor)[0]
        cursor += 4
        name = raw_path.rstrip(b"\x00").decode("utf-8", errors="replace")
        absolute_offset = file_base + offset
        encrypted = bool(entry_flags & 1)
        content_sha = None
        if not encrypted:
            declared_plaintext += size
            if declared_plaintext > expansion_budget:
                raise ValueError("Godot PCK readable entries exceed the expansion budget")
            if absolute_offset + size <= len(data):
                content_sha = hashlib.sha256(
                    data[absolute_offset : absolute_offset + size]
                ).hexdigest()
        entries.append(
            {
                "path": name[6:] if name.startswith("res://") else name,
                "size": size,
                "offset": absolute_offset,
                "md5": None if md5 == b"\x00" * 16 else md5.hex(),
                "sha256": content_sha,
                "hash_status": "hashed" if content_sha else "unknown",
                "flags": entry_flags,
                "encrypted": encrypted,
            }
        )
    return {
        "format": "godot-pck",
        "pck": {
            "format_version": version,
            "engine_major": struct.unpack_from("<I", data, 8)[0],
            "engine_minor": struct.unpack_from("<I", data, 12)[0],
            "engine_patch": struct.unpack_from("<I", data, 16)[0],
            "flags": flags,
            "file_base": file_base,
            "directory_start": directory,
            "declared_file_count": count,
            "directory_status": directory_status,
        },
        "entries": entries,
        "entry_count": len(entries),
        "truncated": count > len(entries),
        "declared_plaintext_bytes": declared_plaintext,
        "expansion_budget_bytes": expansion_budget,
        "encrypted_entry_count": sum(1 for entry in entries if entry["encrypted"]),
    }


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
