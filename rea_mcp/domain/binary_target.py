"""Binary/artifact target identity and format detection.

Detection is pure Python (no third-party binary-parsing dependency) so the MVP is
self-contained. Only a bounded prefix is read for detection; the full-file SHA-256
is streamed separately.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Literal, get_args

from pydantic import BaseModel, ConfigDict

from .analysis_error import AnalysisError, AnalysisInputError
from .canonical import prefixed_digest
from .digests import sha256_file
from .result import Result, err, ok

TargetFormat = Literal[
    "elf",
    "pe",
    "mach-o",
    "mach-o-universal",
    "wasm",
    "zip",
    "apk",
    "asar",
    "sqlite",
    "pcap",
    "plist",
    "har",
    "saz",
    "hap",
    "directory",
    "file",
    "raw-binary",
    "unknown",
]

TargetKind = Literal[
    "executable",
    "library",
    "object",
    "archive",
    "package",
    "database",
    "directory",
    "file",
    "unknown",
]

TARGET_FORMATS: tuple[str, ...] = get_args(TargetFormat)

Detection = tuple["TargetFormat", "str | None", "tuple[str, ...]"]


class BinaryTarget(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str
    source_path: str | None = None
    sha256: str
    kind: TargetKind = "unknown"
    format: TargetFormat = "unknown"
    architecture: str | None = None
    available_architectures: tuple[str, ...] = ()


_ELF_MACHINE: dict[int, str] = {
    0x03: "x86",
    0x3E: "x86_64",
    0x28: "arm",
    0xB7: "arm64",
    0x08: "mips",
    0x14: "powerpc",
    0x15: "powerpc64",
    0xF3: "riscv",
}

_ELF_TYPE_KIND: dict[int, TargetKind] = {1: "object", 2: "executable", 3: "library"}

_PE_MACHINE: dict[int, str] = {
    0x014C: "x86",
    0x8664: "x86_64",
    0x01C0: "arm",
    0xAA64: "arm64",
}

_MACHO_CPU: dict[int, str] = {
    7: "x86",
    0x01000007: "x86_64",
    12: "arm",
    0x0100000C: "arm64",
    18: "powerpc",
    0x01000012: "powerpc64",
}

_MACHO_MAGICS: dict[bytes, str] = {
    b"\xce\xfa\xed\xfe": "<",  # 32-bit little-endian (MH_MAGIC)
    b"\xcf\xfa\xed\xfe": "<",  # 64-bit little-endian (MH_MAGIC_64)
    b"\xfe\xed\xfa\xce": ">",  # 32-bit big-endian (MH_CIGAM)
    b"\xfe\xed\xfa\xcf": ">",  # 64-bit big-endian (MH_CIGAM_64)
}

_FAT_MAGICS = {b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}

_PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4",
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x4d\x3c\xb2\xa1",
    b"\x0a\x0d\x0d\x0a",
}


def detect_format(prefix: bytes) -> Detection:
    """Return ``(format, architecture, available_architectures)`` from a prefix."""

    if prefix[:4] == b"\x7fELF":
        return _detect_elf(prefix)
    if prefix[:2] == b"MZ":
        return _detect_pe(prefix) or ("pe", None, ())
    if prefix[:4] in _MACHO_MAGICS:
        return _detect_macho(prefix)
    if prefix[:4] in _FAT_MAGICS:
        return "mach-o-universal", None, ()
    if prefix[:4] == b"\x00asm":
        return "wasm", None, ()
    if prefix[:4] in _PCAP_MAGICS:
        return "pcap", None, ()
    if prefix[:6] == b"bplist" or prefix[:5] == b"<?xml" or b"<plist" in prefix[:512]:
        return "plist", None, ()
    if prefix[:4] == b"PK\x03\x04":
        return "zip", None, ()
    if prefix[:16] == b"SQLite format 3\x00":
        return "sqlite", None, ()
    return "unknown", None, ()


def _detect_elf(prefix: bytes) -> Detection:
    if len(prefix) < 20:
        return "elf", None, ()
    endian = "<" if prefix[5] == 1 else ">"
    try:
        (_e_type, e_machine) = struct.unpack_from(f"{endian}HH", prefix, 16)
    except struct.error:
        return "elf", None, ()
    arch = _ELF_MACHINE.get(e_machine)
    return "elf", arch, (arch,) if arch else ()


def _detect_pe(prefix: bytes) -> Detection | None:
    if len(prefix) < 0x40:
        return None
    try:
        (e_lfanew,) = struct.unpack_from("<I", prefix, 0x3C)
    except struct.error:
        return None
    if e_lfanew + 6 > len(prefix) or prefix[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return None
    try:
        (machine,) = struct.unpack_from("<H", prefix, e_lfanew + 4)
    except struct.error:
        return None
    arch = _PE_MACHINE.get(machine)
    return "pe", arch, (arch,) if arch else ()


def _detect_macho(prefix: bytes) -> Detection:
    endian = _MACHO_MAGICS[prefix[:4]]
    try:
        (cpu_type,) = struct.unpack_from(f"{endian}I", prefix, 4)
    except struct.error:
        return "mach-o", None, ()
    arch = _MACHO_CPU.get(cpu_type & 0xFFFFFFFF)
    return "mach-o", arch, (arch,) if arch else ()


def _elf_kind(prefix: bytes) -> TargetKind | None:
    if len(prefix) < 18 or prefix[:4] != b"\x7fELF":
        return None
    endian = "<" if prefix[5] == 1 else ">"
    try:
        (e_type,) = struct.unpack_from(f"{endian}H", prefix, 16)
    except struct.error:
        return None
    return _ELF_TYPE_KIND.get(e_type)


def _kind_from_format(target_format: TargetFormat, path: Path, prefix: bytes) -> TargetKind:
    if target_format == "elf":
        kind = _elf_kind(prefix)
        if kind is not None:
            return kind
    if target_format in ("apk", "asar"):
        return "package"
    if target_format == "zip":
        return "archive"
    if target_format == "sqlite":
        return "database"
    if target_format == "wasm":
        return "library"
    if target_format == "directory":
        return "directory"
    suffix = path.suffix.lower()
    if suffix in (".so", ".dylib", ".dll", ".a"):
        return "library"
    if suffix in (".o", ".obj"):
        return "object"
    return "file"


def _classify_zip(path: Path) -> TargetFormat:
    suffix = path.suffix.lower()
    if suffix == ".apk":
        return "apk"
    if suffix == ".asar":
        return "asar"
    if suffix == ".saz":
        return "saz"
    if suffix == ".hap":
        return "hap"
    return "zip"


def _classify_unknown(path: Path) -> TargetFormat:
    suffix = path.suffix.lower()
    if suffix == ".asar":
        return "asar"
    if suffix == ".har":
        return "har"
    return "unknown"


def _detect_directory(path: Path) -> Detection:
    if (path / "package.json").is_file() or (path / "app.asar").exists():
        return "asar", None, ()
    return "directory", None, ()


def parse_binary_target(
    path: str | Path,
    *,
    target_kind: TargetKind | None = None,
    format_hint: TargetFormat | None = None,
) -> Result[BinaryTarget, AnalysisError]:
    """Detect the identity of a local target and compute its digest."""

    resolved = Path(path)
    if not resolved.exists():
        return err(AnalysisInputError(operation="open_binary", message=f"Target not found: {path}"))

    if resolved.is_dir():
        target_format, architecture, architectures = _detect_directory(resolved)
        return ok(
            BinaryTarget(
                path=str(resolved),
                sha256=_directory_digest(resolved),
                kind=target_kind or "directory",
                format=target_format,
                architecture=architecture,
                available_architectures=architectures,
            )
        )

    with open(resolved, "rb") as handle:
        prefix = handle.read(4096)

    if format_hint is not None:
        target_format = format_hint
        architecture, architectures = _arch_info_for_hint(prefix, format_hint)
    else:
        detected, architecture, architectures = detect_format(prefix)
        if detected == "zip":
            target_format = _classify_zip(resolved)
        elif detected == "unknown":
            target_format = _classify_unknown(resolved)
        else:
            target_format = detected

    kind = target_kind or _kind_from_format(target_format, resolved, prefix)
    return ok(
        BinaryTarget(
            path=str(resolved),
            sha256=sha256_file(resolved),
            kind=kind,
            format=target_format,
            architecture=architecture,
            available_architectures=architectures,
        )
    )


def _arch_info_for_hint(prefix: bytes, hint: TargetFormat) -> tuple[str | None, tuple[str, ...]]:
    if hint == "elf":
        _, arch, archs = _detect_elf(prefix)
        return arch, archs
    if hint == "pe":
        pe = _detect_pe(prefix)
        return (pe[1], pe[2]) if pe is not None else (None, ())
    if hint == "mach-o":
        _, arch, archs = _detect_macho(prefix)
        return arch, archs
    return None, ()


def _directory_digest(path: Path) -> str:
    """Bounded identity for a directory: sorted relative names and sizes.

    Not a full content Merkle tree; sufficient to detect structural change for the
    MVP. Returns a bare 64-char SHA-256 hex value.
    """

    entries: list[dict[str, object]] = []
    for child in sorted(path.rglob("*")):
        rel = child.relative_to(path).as_posix()
        if child.is_file():
            entries.append({"path": rel, "size": child.stat().st_size})
        elif child.is_dir():
            entries.append({"path": rel + "/", "kind": "directory"})
    return prefixed_digest("", entries).lstrip("_")


__all__ = [
    "TARGET_FORMATS",
    "BinaryTarget",
    "TargetFormat",
    "TargetKind",
    "detect_format",
    "parse_binary_target",
]
