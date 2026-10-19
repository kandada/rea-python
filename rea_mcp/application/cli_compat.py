"""CLI compatibility commands that do not need a persistent MCP tool.

Covers binary byte utilities, artifact extraction, JS/WASM comparisons, application
graphs, managed/.NET boundaries, and gated native-runtime commands.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import struct
import tarfile
import zipfile
from pathlib import Path
from typing import Any

from ..domain.analysis_error import (
    AnalysisCapabilityUnavailableError,
    AnalysisInputError,
)
from ..domain.binary_target import parse_binary_target
from ..providers.formats.elf import parse_elf
from ..providers.formats.io import open_target
from ..providers.formats.macho import fat_slices, macho_mitigations, parse_macho
from ..providers.formats.pe import parse_pe

_ELF_ARCHES = ("x86", "x86_64", "arm", "arm64", "mips", "powerpc", "powerpc64", "riscv")
_PE_ARCHES = ("x86", "x86_64", "arm64")
_MACHO_ARCHES = ("x86", "x86_64", "arm", "arm64", "powerpc", "powerpc64")


def _target(path: str) -> Any:
    result = parse_binary_target(path)
    if not result.ok:
        raise result.error
    return result.value


def _input(operation: str, message: str) -> AnalysisInputError:
    return AnalysisInputError(operation=operation, message=message)


def list_architectures() -> dict[str, Any]:
    return {
        "elf": list(_ELF_ARCHES),
        "pe": list(_PE_ARCHES),
        "mach-o": list(_MACHO_ARCHES),
    }


def list_objdump_architectures() -> dict[str, Any]:
    from ..process.supervision import run_owned_process
    from ..providers.external import resolve_tool

    resolution = resolve_tool(("objdump",), None)
    if not resolution.available or resolution.path is None:
        return {"available": False, "reason": resolution.reason, "banner": []}
    result = run_owned_process(
        [resolution.path, "--info"], timeout=60, operation="list_objdump_architectures"
    )
    if not result.ok:
        raise result.error
    return {
        "available": True,
        "binary": resolution.path,
        "banner": result.value.stdout.splitlines()[:300],
    }


def _macho_summary(info: Any) -> dict[str, Any]:
    return {
        "architecture": info.architecture,
        "filetype": info.filetype_name,
        "endian": "little" if info.endian == "<" else "big",
        "is_64": info.is_64,
        "entry": hex(info.entry) if info.entry else None,
        "uuid": info.uuid,
        "build_tool": info.build_tool,
        "min_os": info.min_os,
        "has_code_signature": info.has_code_signature,
        "segments": [segment.__dict__ for segment in info.segments],
        "sections": [section.__dict__ for section in info.sections],
        "dylibs": info.dylibs,
        "exports": info.exports[:512],
        "imports": info.imports[:512],
        "mitigations": macho_mitigations(info),
        "limitations": info.limitations,
    }


def inspect_macho(path: str) -> dict[str, Any]:
    with open_target(path) as data:
        info = parse_macho(data)
        if info is not None:
            return {"format": "mach-o", **_macho_summary(info)}
        slices = fat_slices(data)
        if slices:
            summaries = []
            for arch, offset, size in slices[:8]:
                sliced = parse_macho(data[offset : offset + size])
                if sliced is None:
                    continue
                summaries.append(
                    {
                        "architecture": arch,
                        "slice_offset": offset,
                        "slice_size": size,
                        **_macho_summary(sliced),
                    }
                )
            return {
                "format": "mach-o-universal",
                "slice_count": len(slices),
                "slices": summaries,
            }
    raise _input("inspect_macho", "not a Mach-O image")


_SIGNATURE_TYPES = {
    0: "CodeDirectory",
    1: "Info.plist",
    2: "Requirements",
    3: "ResourceDir",
    4: "Application",
    5: "Entitlements",
    7: "DEREntitlements",
    8: "LaunchConstraintSelf",
    9: "LaunchConstraintParent",
    10: "LaunchConstraintResponsible",
    11: "LibraryConstraint",
    0x10000: "CMS",
}
_HASH_TYPES = {1: "sha1", 2: "sha256", 3: "sha256-truncated", 4: "sha384"}


def _cstring(data: bytes, offset: int) -> str | None:
    if offset <= 0 or offset >= len(data):
        return None
    end = data.find(b"\x00", offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode("utf-8", errors="replace")


def _parse_code_directory(blob: bytes) -> dict[str, Any]:
    if len(blob) < 44:
        return {}
    magic, length = struct.unpack_from(">II", blob, 0)
    if magic != 0xFADE0C02:
        return {}
    version = struct.unpack_from(">I", blob, 8)[0]
    flags = struct.unpack_from(">I", blob, 12)[0]
    hash_offset = struct.unpack_from(">I", blob, 16)[0]
    ident_offset = struct.unpack_from(">I", blob, 20)[0]
    n_special = struct.unpack_from(">I", blob, 24)[0]
    n_code = struct.unpack_from(">I", blob, 28)[0]
    code_limit = struct.unpack_from(">I", blob, 32)[0]
    hash_size = blob[36]
    hash_type = blob[37]
    platform = blob[38]
    page_size = blob[39]
    team_offset = (
        struct.unpack_from(">I", blob, 48)[0] if version >= 0x20200 and len(blob) >= 52 else 0
    )
    algorithm = _HASH_TYPES.get(hash_type, f"type-{hash_type}")
    digest = (
        hashlib.sha1(blob[:length]).digest()
        if hash_type == 1
        else hashlib.sha256(blob[:length]).digest()[:20]
    )
    return {
        "version": f"0x{version:x}",
        "flags": flags,
        "identifier": _cstring(blob, ident_offset),
        "team_id": _cstring(blob, team_offset) if team_offset else None,
        "hash_type": algorithm,
        "hash_size": hash_size,
        "page_size": page_size,
        "platform": platform,
        "code_limit": code_limit,
        "special_slots": n_special,
        "code_slots": n_code,
        "hash_offset": hash_offset,
        "cdhash": digest.hex(),
    }


def _signature_for(data: Any, info: Any) -> dict[str, Any]:
    endian = info.endian
    header_size = 32 if info.is_64 else 28
    offset = header_size
    signature_blob: bytes | None = None
    for _ in range(info.ncmds):
        if offset + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from(endian + "II", data, offset)
        if cmdsize < 8:
            break
        if cmd == 0x1D and offset + 16 <= len(data):  # LC_CODE_SIGNATURE
            dataoff, datasize = struct.unpack_from(endian + "II", data, offset + 8)
            if dataoff + datasize <= len(data):
                signature_blob = bytes(data[dataoff : dataoff + datasize])
            break
        offset += cmdsize
    result: dict[str, Any] = {
        "has_code_signature": info.has_code_signature,
        "blob_size": len(signature_blob) if signature_blob else 0,
        "blobs": [],
        "code_directory": None,
        "entitlements": None,
    }
    if not signature_blob or len(signature_blob) < 12:
        return result
    magic, _length, count = struct.unpack_from(">III", signature_blob, 0)
    if magic != 0xFADE0CC0:
        return result
    for index in range(count):
        entry_offset = 12 + index * 8
        if entry_offset + 8 > len(signature_blob):
            break
        blob_type, blob_offset = struct.unpack_from(">II", signature_blob, entry_offset)
        if blob_offset + 8 > len(signature_blob):
            continue
        blob_magic, blob_length = struct.unpack_from(">II", signature_blob, blob_offset)
        blob = signature_blob[blob_offset : blob_offset + blob_length]
        result["blobs"].append(
            {
                "type": _SIGNATURE_TYPES.get(blob_type, f"type-{blob_type}"),
                "type_id": blob_type,
                "offset": blob_offset,
                "length": blob_length,
                "magic": f"0x{blob_magic:08x}",
            }
        )
        if blob_type == 0:
            result["code_directory"] = _parse_code_directory(blob)
        elif blob_type == 5 and len(blob) > 8:
            import plistlib

            try:
                result["entitlements"] = plistlib.loads(blob[8:])
            except Exception:
                result["entitlements"] = {"raw_hex": blob[8:].hex()[:4000]}
    return result


def inspect_signature(path: str) -> dict[str, Any]:
    with open_target(path) as data:
        info = parse_macho(data)
        if info is not None:
            return {"format": "mach-o", **_signature_for(data, info)}
        slices = fat_slices(data)
        if slices:
            results = []
            for arch, offset, size in slices[:8]:
                sliced = parse_macho(data[offset : offset + size])
                if sliced is None:
                    continue
                results.append(
                    {
                        "architecture": arch,
                        "slice_offset": offset,
                        "slice_size": size,
                        **_signature_for(data[offset : offset + size], sliced),
                    }
                )
            return {"format": "mach-o-universal", "slices": results}
    raise _input("inspect_signature", "not a Mach-O image")


def _map_address(fmt: str, data: Any, address: int) -> tuple[int | None, str | None]:
    if fmt == "elf":
        elf = parse_elf(data)
        if elf is None:
            return None, None
        for elf_section in elf.sections:
            if (
                elf_section.size
                and elf_section.addr <= address < elf_section.addr + elf_section.size
            ):
                return elf_section.offset + (address - elf_section.addr), elf_section.name
        for elf_segment in elf.segments:
            if (
                elf_segment.filesz
                and elf_segment.vaddr <= address < elf_segment.vaddr + elf_segment.filesz
            ):
                return elf_segment.offset + (address - elf_segment.vaddr), None
        return None, None
    if fmt == "pe":
        pe_info = parse_pe(data)
        if pe_info is None:
            return None, None
        rva = address - pe_info.image_base if address >= pe_info.image_base else address
        for pe_section in pe_info.sections:
            if (
                pe_section.virtual_address
                <= rva
                < pe_section.virtual_address + pe_section.virtual_size
            ):
                delta = rva - pe_section.virtual_address
                if delta < pe_section.size_of_raw_data:
                    return pe_section.pointer_to_raw_data + delta, pe_section.name
        return None, None
    if fmt == "mach-o-universal":
        slices = fat_slices(data)
        if not slices:
            return None, None
        for _arch, base, size in slices:
            mac = parse_macho(data[base : base + size])
            if mac is None:
                continue
            for mac_segment in mac.segments:
                if (
                    mac_segment.filesize
                    and mac_segment.vmaddr <= address < mac_segment.vmaddr + mac_segment.filesize
                ):
                    return (
                        base + mac_segment.fileoff + (address - mac_segment.vmaddr),
                        mac_segment.name,
                    )
        return None, None
    if fmt == "mach-o":
        mac = parse_macho(data)
        if mac is None:
            return None, None
        for mac_segment in mac.segments:
            if (
                mac_segment.filesize
                and mac_segment.vmaddr <= address < mac_segment.vmaddr + mac_segment.filesize
            ):
                return mac_segment.fileoff + (address - mac_segment.vmaddr), mac_segment.name
        return None, None
    return None, None


def address_to_file_offset(path: str, address: str) -> dict[str, Any]:
    target = _target(path)
    value = int(str(address), 0)
    with open_target(path) as data:
        offset, section = _map_address(target.format, data, value)
    return {
        "format": target.format,
        "address": value,
        "file_offset": offset,
        "section": section,
        "mapped": offset is not None,
    }


def _offset_to_address(fmt: str, data: Any, offset: int) -> int | None:
    if fmt == "elf":
        elf = parse_elf(data)
        if elf is None:
            return None
        for elf_section in elf.sections:
            if (
                elf_section.size
                and elf_section.offset <= offset < elf_section.offset + elf_section.size
            ):
                return elf_section.addr + (offset - elf_section.offset)
        return None
    if fmt == "pe":
        pe_info = parse_pe(data)
        if pe_info is None:
            return None
        for pe_section in pe_info.sections:
            if (
                pe_section.size_of_raw_data
                and pe_section.pointer_to_raw_data
                <= offset
                < pe_section.pointer_to_raw_data + pe_section.size_of_raw_data
            ):
                rva = pe_section.virtual_address + (offset - pe_section.pointer_to_raw_data)
                return pe_info.image_base + rva
        return None
    if fmt == "mach-o-universal":
        for _arch, base, size in fat_slices(data) or []:
            if not (base <= offset < base + size):
                continue
            mac = parse_macho(data[base : base + size])
            if mac is None:
                continue
            local = offset - base
            for mac_segment in mac.segments:
                if (
                    mac_segment.filesize
                    and mac_segment.fileoff <= local < mac_segment.fileoff + mac_segment.filesize
                ):
                    return mac_segment.vmaddr + (local - mac_segment.fileoff)
        return None
    if fmt == "mach-o":
        mac = parse_macho(data)
        if mac is None:
            return None
        for mac_segment in mac.segments:
            if (
                mac_segment.filesize
                and mac_segment.fileoff <= offset < mac_segment.fileoff + mac_segment.filesize
            ):
                return mac_segment.vmaddr + (offset - mac_segment.fileoff)
        return None
    return None


def read_bytes(
    path: str,
    offset: int | None = None,
    length: int = 64,
    *,
    address: str | None = None,
) -> dict[str, Any]:
    if length < 0 or length > 10_000_000:
        raise _input("read_bytes", "length out of range")
    target = _target(path)
    resolved = offset
    virtual: int | None = None
    if address is not None:
        virtual = int(str(address), 0)
        with open_target(path) as data:
            resolved, _section = _map_address(target.format, data, virtual)
        if resolved is None:
            raise _input("read_bytes", f"address {address} does not map to a file offset")
    if resolved is None:
        raise _input("read_bytes", "provide --offset or --address")
    if resolved < 0:
        raise _input("read_bytes", "offset out of range")
    with open_target(path) as data:
        chunk = bytes(data[resolved : resolved + length])
        mapped = _offset_to_address(target.format, data, resolved)
    return {
        "offset": resolved,
        "address": virtual if virtual is not None else mapped,
        "length": len(chunk),
        "hex": chunk.hex(),
        "ascii": "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk),
    }


def search_bytes(
    path: str,
    pattern: str,
    *,
    hex_pattern: bool = False,
    limit: int = 100,
    address: str | None = None,
) -> dict[str, Any]:
    needle = bytes.fromhex(pattern) if hex_pattern else pattern.encode("utf-8")
    if not needle:
        raise _input("search_bytes", "pattern is required")
    target = _target(path)
    start_offset = 0
    if address is not None:
        with open_target(path) as data:
            mapped, _section = _map_address(target.format, data, int(str(address), 0))
        if mapped is None:
            raise _input("search_bytes", f"address {address} does not map to a file offset")
        start_offset = mapped
    hits: list[dict[str, Any]] = []
    with open_target(path) as data:
        position = start_offset
        while len(hits) < limit:
            index = data.find(needle, position)
            if index < 0:
                break
            hits.append(
                {
                    "file_offset": index,
                    "virtual_address": _offset_to_address(target.format, data, index),
                }
            )
            position = index + 1
    return {
        "pattern": pattern,
        "hex": hex_pattern,
        "start_offset": start_offset,
        "hits": hits,
        "match_count": len(hits),
    }


def demangle_swift(symbols: list[str]) -> dict[str, Any]:
    import subprocess

    candidates: list[list[str]] = []
    xcrun = shutil.which("xcrun")
    if xcrun:
        try:
            found = subprocess.run(
                [xcrun, "--find", "swift-demangle"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if found.returncode == 0 and found.stdout.strip():
                candidates.append([found.stdout.strip()])
        except (OSError, subprocess.TimeoutExpired):
            pass
    direct = shutil.which("swift-demangle")
    if direct:
        candidates.append([direct])
    for command in candidates:
        try:
            result = subprocess.run(
                [*command, *symbols],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0:
            return {
                "symbols": symbols,
                "demangled": result.stdout.splitlines(),
                "binary": command[0],
                "limitation": None,
            }
    return {
        "symbols": symbols,
        "demangled": None,
        "limitation": "swift-demangle is unavailable; install Xcode command-line tools.",
    }


def _is_dmg_file(path: Path) -> bool:
    try:
        if path.stat().st_size < 512:
            return False
        with path.open("rb") as handle:
            handle.seek(-512, 2)
            return handle.read(4) == b"koly"
    except OSError:
        return False


def _extract_dmg(path: Path, destination: Path, *, overwrite: bool) -> dict[str, Any]:
    import shutil
    import subprocess
    import sys
    import tempfile

    if sys.platform != "darwin":
        raise _input("extract_artifact", "DMG extraction requires macOS hdiutil")
    hdiutil = shutil.which("hdiutil")
    if not hdiutil:
        raise _input("extract_artifact", "hdiutil is unavailable")
    mountpoint = Path(tempfile.mkdtemp(prefix="rea-mcp-dmg-"))
    extracted: list[str] = []
    try:
        attached = subprocess.run(
            [
                hdiutil,
                "attach",
                "-nobrowse",
                "-readonly",
                "-noverify",
                "-mountpoint",
                str(mountpoint),
                str(path),
            ],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        if attached.returncode != 0:
            raise _input(
                "extract_artifact",
                f"hdiutil attach failed: {attached.stderr[-500:]}",
            )
        for child in mountpoint.rglob("*"):
            if not child.is_file() or child.is_symlink():
                continue
            relative = child.relative_to(mountpoint)
            target = destination / relative
            if target.exists() and not overwrite:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(child, target)
            extracted.append(str(target))
    finally:
        subprocess.run(
            [hdiutil, "detach", str(mountpoint)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        shutil.rmtree(mountpoint, ignore_errors=True)
    return {
        "format": "dmg",
        "output_directory": str(destination),
        "extracted": extracted,
        "extracted_count": len(extracted),
    }


def extract_artifact(path: str, output: str, *, overwrite: bool = False) -> dict[str, Any]:
    destination = Path(output).expanduser()
    destination.mkdir(parents=True, exist_ok=True)
    if _is_dmg_file(Path(path)):
        return _extract_dmg(Path(path), destination, overwrite=overwrite)
    extracted: list[str] = []

    def safe(name: str) -> Path:
        candidate = (destination / name).resolve()
        if destination.resolve() not in candidate.parents and candidate != destination.resolve():
            raise _input("extract_artifact", f"unsafe archive member: {name}")
        return candidate

    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zip_archive:
            for info in zip_archive.infolist():
                if info.is_dir():
                    continue
                target_path = safe(info.filename)
                if target_path.exists() and not overwrite:
                    continue
                target_path.parent.mkdir(parents=True, exist_ok=True)
                with zip_archive.open(info) as source, target_path.open("wb") as sink:
                    shutil.copyfileobj(source, sink)
                extracted.append(str(target_path))
    elif tarfile.is_tarfile(path):
        with tarfile.open(path) as tar_archive:
            for member in tar_archive.getmembers():
                if not member.isfile():
                    continue
                target_path = safe(member.name)
                if target_path.exists() and not overwrite:
                    continue
                target_path.parent.mkdir(parents=True, exist_ok=True)
                tar_source = tar_archive.extractfile(member)
                if tar_source is None:
                    continue
                with tar_source, target_path.open("wb") as sink:
                    shutil.copyfileobj(tar_source, sink)
                extracted.append(str(target_path))
    else:
        raise _input("extract_artifact", "only zip and tar archives are supported")
    return {
        "output_directory": str(destination),
        "extracted": extracted,
        "extracted_count": len(extracted),
    }


def _uleb(data: bytes, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            break
        shift += 7
    return result, offset


def _wasm_interface(path: str) -> dict[str, Any]:
    data = Path(path).read_bytes()
    if data[:4] != b"\x00asm":
        raise _input("compare_wasm_interfaces", f"not a WASM module: {path}")
    exports: set[str] = set()
    imports: set[str] = set()
    offset = 8
    while offset < len(data):
        section_id = data[offset]
        offset += 1
        size, offset = _uleb(data, offset)
        end = offset + size
        if section_id == 7:  # export
            count, cursor = _uleb(data, offset)
            for _ in range(count):
                name_len, cursor = _uleb(data, cursor)
                exports.add(data[cursor : cursor + name_len].decode("utf-8", "replace"))
                cursor += name_len + 1
        elif section_id == 2:  # import
            count, cursor = _uleb(data, offset)
            for _ in range(count):
                module_len, cursor = _uleb(data, cursor)
                module = data[cursor : cursor + module_len].decode("utf-8", "replace")
                cursor += module_len
                name_len, cursor = _uleb(data, cursor)
                name = data[cursor : cursor + name_len].decode("utf-8", "replace")
                cursor += name_len
                kind = data[cursor]
                cursor += 1
                if kind == 0:
                    _, cursor = _uleb(data, cursor)
                elif kind == 1:
                    cursor += 1
                    flags, cursor = _uleb(data, cursor)
                    _, cursor = _uleb(data, cursor)
                    if flags & 1:
                        _, cursor = _uleb(data, cursor)
                elif kind == 2:
                    flags, cursor = _uleb(data, cursor)
                    _, cursor = _uleb(data, cursor)
                    if flags & 1:
                        _, cursor = _uleb(data, cursor)
                elif kind == 3:
                    cursor += 2
                imports.add(f"{module}.{name}")
        offset = end
    return {"exports": sorted(exports), "imports": sorted(imports)}


def compare_wasm_interfaces(left: str, right: str) -> dict[str, Any]:
    a = _wasm_interface(left)
    b = _wasm_interface(right)
    return {
        "left": {"export_count": len(a["exports"]), "import_count": len(a["imports"])},
        "right": {"export_count": len(b["exports"]), "import_count": len(b["imports"])},
        "added_exports": sorted(set(b["exports"]) - set(a["exports"])),
        "removed_exports": sorted(set(a["exports"]) - set(b["exports"])),
        "added_imports": sorted(set(b["imports"]) - set(a["imports"])),
        "removed_imports": sorted(set(a["imports"]) - set(b["imports"])),
    }


_EXPORT_RE = re.compile(
    r"export\s+(?:default\s+)?(?:async\s+)?(?:const|let|var|function|class)\s+([A-Za-z_$][\w$]*)"
)
_EXPORT_LIST_RE = re.compile(r"export\s*\{([^}]*)\}")


def _js_exports(path: Path) -> set[str]:
    files = [path] if path.is_file() else sorted(path.rglob("*.js"))
    names: set[str] = set()
    for file in files[:1000]:
        try:
            text = file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        names.update(_EXPORT_RE.findall(text))
        for group in _EXPORT_LIST_RE.findall(text):
            for item in group.split(","):
                item = item.strip().split(" as ")[-1].strip()
                if item:
                    names.add(item)
    return names


def compare_javascript_export_shapes(left: str, right: str) -> dict[str, Any]:
    a = _js_exports(Path(left))
    b = _js_exports(Path(right))
    return {
        "status": "unchanged" if a == b else "changed",
        "left": sorted(a),
        "right": sorted(b),
        "added": sorted(b - a),
        "removed": sorted(a - b),
    }


def compare_source_to_bundle(source: str, bundle: str) -> dict[str, Any]:
    source_root = Path(source)
    source_files = [source_root] if source_root.is_file() else sorted(source_root.rglob("*"))
    source_names = {
        file.stem
        for file in source_files
        if file.is_file() and file.suffix in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")
    }
    bundle_path = Path(bundle)
    from ..providers.javascript import JavaScriptApplicationProvider

    result = JavaScriptApplicationProvider().analyze(
        "analyze_javascript_application", _target(str(bundle_path)), {}, None
    )
    if not result.ok:
        raise result.error
    modules = set((result.value.result.get("modules") or {}).keys())
    module_names = {Path(name).stem for name in modules}
    return {
        "source_files": sorted(source_names),
        "bundle_modules": sorted(modules),
        "matched": sorted(source_names & module_names),
        "source_only": sorted(source_names - module_names),
        "bundle_only": sorted(module_names - source_names),
    }


def compare_application_versions(left: str, right: str) -> dict[str, Any]:
    left_path = Path(left)
    right_path = Path(right)
    if left_path.suffix in (".apk", ".hap") and right_path.suffix in (".apk", ".hap"):
        from ..providers.android import AndroidProvider
        from ..providers.harmony import HarmonyProvider

        provider = HarmonyProvider() if left_path.suffix == ".hap" else AndroidProvider()
        first = provider.analyze(
            "inspect_harmony_package" if left_path.suffix == ".hap" else "inspect_android_package",
            _target(str(left_path)),
            {},
            None,
        )
        second = provider.analyze(
            "inspect_harmony_package" if right_path.suffix == ".hap" else "inspect_android_package",
            _target(str(right_path)),
            {},
            None,
        )
        if not first.ok:
            raise first.error
        if not second.ok:
            raise second.error
        return {
            "left": first.value.result,
            "right": second.value.result,
            "changed": first.value.result != second.value.result,
        }
    from .workflows import compare_bundles

    return compare_bundles(left, right)


def trace_javascript_semantics(path: str) -> dict[str, Any]:
    from ..providers.javascript import JavaScriptApplicationProvider

    result = JavaScriptApplicationProvider().analyze(
        "analyze_javascript_application", _target(path), {}, None
    )
    if not result.ok:
        raise result.error
    data = result.value.result
    return {
        "modules": data.get("modules"),
        "edges": data.get("edges"),
        "electron": data.get("electron"),
        "module_count": data.get("module_count"),
        "edge_count": data.get("edge_count"),
    }


def project_android_application_graph(path: str) -> dict[str, Any]:
    from ..providers.android import AndroidProvider

    result = AndroidProvider().analyze("inspect_android_package", _target(path), {}, None)
    if not result.ok:
        raise result.error
    facts = result.value.result
    package = facts.get("package") or Path(path).stem
    nodes = [{"id": package, "kind": "package"}]
    edges = []
    for name in facts.get("dex_files") or []:
        nodes.append({"id": name, "kind": "dex"})
        edges.append({"from": package, "to": name, "kind": "contains"})
    for name in facts.get("native_libraries") or []:
        nodes.append({"id": name, "kind": "native-library"})
        edges.append({"from": package, "to": name, "kind": "contains"})
    components = facts.get("components") or {}
    for kind, entries in components.items():
        for entry in entries or []:
            name = entry.get("name")
            if not name:
                continue
            nodes.append(
                {
                    "id": name,
                    "kind": kind.rstrip("s") or "component",
                    "exported": entry.get("exported"),
                    "permission": entry.get("permission"),
                }
            )
            edges.append({"from": package, "to": name, "kind": "contains"})
            if entry.get("permission"):
                edges.append(
                    {"from": name, "to": entry["permission"], "kind": "requires-permission"}
                )
    for permission in facts.get("permissions") or []:
        nodes.append({"id": permission, "kind": "permission"})
        edges.append({"from": package, "to": permission, "kind": "uses-permission"})
    return {"root": package, "nodes": nodes, "edges": edges, "facts": facts}


def project_apple_application_graph(path: str) -> dict[str, Any]:
    import plistlib

    root = Path(path).expanduser()
    if not root.is_dir():
        raise _input("project_apple_application_graph", "expected an .app directory")
    info_plist: dict[str, Any] = {}
    plist_path = root / "Info.plist"
    if plist_path.is_file():
        try:
            parsed = plistlib.loads(plist_path.read_bytes())
            if isinstance(parsed, dict):
                info_plist = parsed
        except (OSError, ValueError):
            info_plist = {}
    bundle_id = str(info_plist.get("CFBundleIdentifier") or root.stem)
    executable = str(info_plist.get("CFBundleExecutable") or "")
    nodes: list[dict[str, Any]] = [{"id": bundle_id, "kind": "bundle"}]
    edges: list[dict[str, Any]] = []
    if executable:
        executable_path = root / executable
        nodes.append({"id": executable, "kind": "executable"})
        edges.append({"from": bundle_id, "to": executable, "kind": "contains"})
        if executable_path.is_file():
            try:
                with open_target(str(executable_path)) as data:
                    macho = parse_macho(data)
            except OSError:
                macho = None
            if macho is not None:
                nodes[-1]["architecture"] = macho.architecture
                for dylib in macho.dylibs[:200]:
                    nodes.append({"id": dylib, "kind": "dylib"})
                    edges.append({"from": executable, "to": dylib, "kind": "links"})
    for candidate in sorted(root.rglob("*")):
        if candidate.is_file() and candidate.suffix == ".dylib":
            if not any(node["id"] == candidate.name for node in nodes):
                nodes.append({"id": candidate.name, "kind": "dylib"})
                edges.append({"from": bundle_id, "to": candidate.name, "kind": "links"})
        elif candidate.is_dir() and candidate.suffix == ".framework":
            nodes.append({"id": candidate.name, "kind": "framework"})
            edges.append({"from": bundle_id, "to": candidate.name, "kind": "links"})
    return {
        "root": str(root),
        "bundle_id": bundle_id,
        "executable": executable or None,
        "version": info_plist.get("CFBundleShortVersionString"),
        "minimum_os": info_plist.get("LSMinimumSystemVersion"),
        "url_types": info_plist.get("CFBundleURLTypes") or [],
        "info": info_plist,
        "nodes": nodes,
        "edges": edges,
    }


def project_harmony_application_graph(path: str) -> dict[str, Any]:
    from ..providers.harmony import HarmonyProvider

    result = HarmonyProvider().analyze("inspect_harmony_package", _target(path), {}, None)
    if not result.ok:
        raise result.error
    facts = result.value.result
    package = facts.get("bundle_name") or Path(path).stem
    nodes = [{"id": package, "kind": "package"}]
    edges = []
    for name in facts.get("abc_files") or []:
        nodes.append({"id": name, "kind": "abc"})
        edges.append({"from": package, "to": name, "kind": "contains"})
    for name in facts.get("native_libraries") or []:
        nodes.append({"id": name, "kind": "native-library"})
        edges.append({"from": package, "to": name, "kind": "contains"})
    for ability in facts.get("abilities") or []:
        name = ability.get("name") if isinstance(ability, dict) else None
        if not name:
            continue
        nodes.append({"id": str(name), "kind": "ability", "exported": ability.get("exported")})
        edges.append({"from": package, "to": str(name), "kind": "contains"})
    return {"root": package, "nodes": nodes, "edges": edges, "facts": facts}


def project_managed_application_graph(path: str) -> dict[str, Any]:
    from ..providers.dotnet import ManagedStaticProvider

    members = ManagedStaticProvider().analyze("inspect_managed_members", _target(path), {}, None)
    if not members.ok:
        raise members.error
    data = members.value.result
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    for type_entry in data.get("types") or []:
        type_name = str(type_entry.get("full_name") or type_entry.get("name") or "")
        if not type_name:
            continue
        nodes.append({"id": type_name, "kind": "type"})
        for method in type_entry.get("methods") or []:
            method_name = method.get("name") if isinstance(method, dict) else method
            if not method_name:
                continue
            method_id = f"{type_name}::{method_name}"
            nodes.append({"id": method_id, "kind": "method"})
            edges.append({"from": type_name, "to": method_id, "kind": "declares"})
    return {"nodes": nodes, "edges": edges, "member_facts": data}


def import_managed_reconstruction(path: str) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    from ..domain.reconstruction import (
        Obligation,
        ReconstructionLedger,
        build_ledger,
        evaluate_coverage,
    )

    if isinstance(payload, dict) and "obligations" in payload:
        items = payload["obligations"]
        if items and isinstance(items[0], dict) and "status" in items[0]:
            ledger = ReconstructionLedger.model_validate(payload)
        else:
            ledger = build_ledger([Obligation.model_validate(item) for item in items])
    else:
        raise _input("import_managed_reconstruction", "expected a ledger or obligation list")
    return {"ledger": ledger.model_dump(), "coverage": evaluate_coverage(ledger)}


def _pinvoke_rows(path: str) -> list[dict[str, Any]] | None:
    from ..providers.dotnet import _metadata_streams
    from ..providers.formats.cli_metadata import parse_pinvoke
    from ..providers.formats.pe import parse_pe

    data = Path(path).read_bytes()
    pe = parse_pe(data)
    if pe is None or not pe.has_clr:
        return None
    parsed = _metadata_streams(data, pe)
    if parsed is None:
        return None
    return parse_pinvoke(data, parsed[1])


def inspect_managed_native_boundaries_for_bytes(data: bytes) -> dict[str, Any]:
    from ..providers.dotnet import _metadata_streams
    from ..providers.formats.cli_metadata import parse_pinvoke
    from ..providers.formats.pe import parse_pe

    pe = parse_pe(data)
    pinvoke: list[dict[str, Any]] | None = None
    if pe is not None and pe.has_clr:
        parsed = _metadata_streams(data, pe)
        if parsed is not None:
            pinvoke = parse_pinvoke(data, parsed[1])
    return {
        "pinvoke": pinvoke or [],
        "pinvoke_count": len(pinvoke or []),
        "has_clr": bool(pe and pe.has_clr),
    }


def verify_managed_native_boundaries_for_bytes(
    data: bytes, boundaries: list[str]
) -> dict[str, Any]:
    from ..providers.dotnet import _metadata_streams
    from ..providers.formats.cli_metadata import parse_pinvoke
    from ..providers.formats.pe import parse_pe

    pinvoke: list[dict[str, Any]] = []
    pe = parse_pe(data)
    if pe is not None and pe.has_clr:
        parsed = _metadata_streams(data, pe)
        if parsed is not None:
            pinvoke = parse_pinvoke(data, parsed[1]) or []
    declared = {str(item.get("method")) for item in pinvoke if item.get("method")} | {
        str(item.get("entry_point")) for item in pinvoke if item.get("entry_point")
    }
    results = [
        {
            "boundary": name,
            "present": name in declared if declared else name.encode("utf-8") in data,
            "source": "implmap" if declared else "heuristic",
        }
        for name in boundaries
    ]
    return {"verified": all(item["present"] for item in results), "boundaries": results}


def inspect_managed_native_boundaries(path: str) -> dict[str, Any]:
    data = Path(path).read_bytes()
    pinvoke = _pinvoke_rows(path)
    markers = {
        "dllimport_attribute": data.count(b"DllImportAttribute"),
        "library_import_attribute": data.count(b"LibraryImportAttribute"),
        "impl_map": data.count(b"ImplMap"),
        "internal": data.count(b"__Internal"),
    }
    strings = sorted(
        {
            match.decode("ascii", "replace")
            for match in re.findall(rb"[\x20-\x7e]{4,}", data)
            if any(key in match for key in (b"DllImport", b"LibraryImport", b"__Internal"))
        }
    )
    return {
        "pinvoke": pinvoke or [],
        "pinvoke_count": len(pinvoke or []),
        "markers": markers,
        "strings": strings[:200],
        "limitations": (
            [] if pinvoke else ["No ImplMap rows decoded; marker strings are heuristic only."]
        ),
    }


def verify_managed_native_boundaries(path: str, boundaries: list[str]) -> dict[str, Any]:
    data = Path(path).read_bytes()
    pinvoke = _pinvoke_rows(path) or []
    declared = {str(item.get("method")) for item in pinvoke if item.get("method")} | {
        str(item.get("entry_point")) for item in pinvoke if item.get("entry_point")
    }
    results = []
    for name in boundaries:
        present = name in declared if declared else name.encode("utf-8") in data
        results.append(
            {"boundary": name, "present": present, "source": "implmap" if declared else "heuristic"}
        )
    return {"verified": all(item["present"] for item in results), "boundaries": results}


def _dispatch_for(data: Any, info: Any) -> dict[str, Any]:
    if info is None:
        return {"classes": [], "selectors": [], "sections": []}
    raw_sections = {
        section.name: bytes(data[section.offset : section.offset + section.size])
        for section in info.sections
        if section.size
    }
    section_names = sorted({section.name for section in info.sections})

    def strings(section_name: str) -> list[str]:
        raw = raw_sections.get(section_name)
        if raw is None:
            return []
        return [item.decode("utf-8", "replace") for item in raw.split(b"\x00") if item][:2000]

    classes = strings("__objc_classname")
    methods = strings("__objc_methname")
    return {
        "sections": section_names[:500],
        "classes": classes,
        "class_count": len(classes),
        "selectors": methods,
        "selector_count": len(methods),
        "has_objc": bool(classes or methods),
    }


def inspect_native_dispatch_metadata(path: str) -> dict[str, Any]:
    with open_target(path) as data:
        info = parse_macho(data)
        if info is not None:
            return _dispatch_for(data, info)
        slices = fat_slices(data)
        if slices:
            merged: dict[str, Any] = {
                "format": "mach-o-universal",
                "slices": [],
                "classes": [],
                "selectors": [],
            }
            for arch, base, size in slices[:8]:
                sliced = parse_macho(data[base : base + size])
                part = _dispatch_for(data[base : base + size], sliced)
                merged["slices"].append(
                    {
                        "architecture": arch,
                        "class_count": part["class_count"],
                        "selector_count": part["selector_count"],
                    }
                )
                merged["classes"].extend(part["classes"])
                merged["selectors"].extend(part["selectors"])
            merged["class_count"] = len(merged["classes"])
            merged["selector_count"] = len(merged["selectors"])
            merged["has_objc"] = bool(merged["classes"] or merged["selectors"])
            merged["limitations"] = (
                [] if merged["has_objc"] else ["No Objective-C class/selector sections were found."]
            )
            return merged
    raise _input("inspect_native_dispatch_metadata", "not a Mach-O image")


def _gated(operation: str, reason: str, remediation: str) -> AnalysisCapabilityUnavailableError:
    return AnalysisCapabilityUnavailableError(
        message=reason,
        provider_id="native-runtime",
        operation=operation,
        reason="provider_unavailable",
        remediation_action=remediation,
    )


def trace_dylib_resolution(
    path: str,
    *,
    allow_execute: bool = False,
    args: list[str] | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    import os
    import subprocess

    if not allow_execute:
        raise _input(
            "trace_dylib_resolution",
            "executing the target requires --allow-execute",
        )
    environment = dict(os.environ, DYLD_PRINT_LIBRARIES="1", DYLD_PRINT_LIBRARIES_POST_LAUNCH="1")
    try:
        completed = subprocess.run(
            [path, *(args or [])],
            capture_output=True,
            text=True,
            timeout=min(timeout, 300.0),
            env=environment,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as cause:
        raise _input("trace_dylib_resolution", str(cause)) from cause
    libraries = sorted(
        {
            line.split(":", 2)[-1].strip()
            for line in completed.stderr.splitlines()
            if ".dylib" in line or ".framework" in line
        }
    )
    return {
        "exit_code": completed.returncode,
        "libraries": libraries[:2000],
        "library_count": len(libraries),
        "stderr_tail": completed.stderr[-4000:],
    }


_NATIVE_CALL_SCRIPT = """
(function () {
  try {
    var objc = Module.findGlobalExportByName('objc_msgSend');
    if (objc) {
      Interceptor.attach(objc, {
        onEnter: function (args) {
          try {
            var sel = ObjC.selectorAsString(args[1]);
            if (sel) send({ type: 'selector', value: sel });
          } catch (e) {}
        }
      });
    }
  } catch (e) {}
  try {
    var dlopen = Module.findGlobalExportByName('dlopen');
    if (dlopen) {
      Interceptor.attach(dlopen, {
        onEnter: function (args) {
          try {
            var p = args[0].readCString();
            if (p) send({ type: 'dlopen', value: p });
          } catch (e) {}
        }
      });
    }
  } catch (e) {}
  send({ type: 'ready' });
})();
"""


def observe_native_calls(
    target: str,
    *,
    args: list[str] | None = None,
    duration: float = 3.0,
    spawn: bool = False,
    allow_execute: bool = False,
    timeout: float = 20.0,
) -> dict[str, Any]:
    import threading
    import time

    if spawn and not allow_execute:
        raise _input("observe_native_calls", "spawning the target requires --allow-execute")
    try:
        import frida
    except ImportError as cause:
        raise _gated(
            "observe_native_calls",
            "the optional 'frida' package is not installed",
            "Install frida in the runtime that executes the CLI.",
        ) from cause

    duration = min(max(duration, 0.1), 120.0)

    def collect(device: Any, pid: int, session: Any) -> dict[str, Any]:
        messages: list[dict[str, Any]] = []
        script = session.create_script(_NATIVE_CALL_SCRIPT)
        script.on("message", lambda message, data: messages.append(message))
        script.load()
        time.sleep(duration)
        selectors: dict[str, int] = {}
        libraries: set[str] = set()
        for message in messages:
            payload = message.get("payload") if isinstance(message, dict) else None
            if not isinstance(payload, dict):
                continue
            if payload.get("type") == "selector":
                value = str(payload.get("value") or "")
                selectors[value] = selectors.get(value, 0) + 1
            elif payload.get("type") == "dlopen":
                libraries.add(str(payload.get("value") or ""))
        return {
            "pid": pid,
            "duration": duration,
            "selector_count": len(selectors),
            "selectors": [
                {"selector": name, "count": count}
                for name, count in sorted(selectors.items(), key=lambda item: -item[1])[:200]
            ],
            "libraries": sorted(libraries)[:500],
        }

    try:
        device = frida.get_local_device()
        if spawn:
            holder: dict[str, Any] = {}

            def worker() -> None:
                try:
                    pid = device.spawn([target, *(args or [])])
                    session = device.attach(pid)
                    device.resume(pid)
                    holder["result"] = collect(device, pid, session)
                    session.detach()
                except Exception as cause:
                    holder["error"] = cause

            thread = threading.Thread(target=worker, daemon=True)
            thread.start()
            thread.join(timeout=duration + max(timeout, 5.0))
            if thread.is_alive():
                raise _gated(
                    "observe_native_calls",
                    "timed out waiting for Frida to spawn/attach the target",
                    "Check task_for_pid permissions or run the target outside a hardened runtime.",
                )
            if "error" in holder:
                raise _gated(
                    "observe_native_calls",
                    f"Frida observation failed: {holder['error']}",
                    "Grant task_for_pid/entitlements or disable SIP restrictions for the target.",
                )
            result: dict[str, Any] = holder.get("result") or {}
            return result
        pid = int(target) if str(target).isdigit() else device.get_process(str(target)).pid
        session = device.attach(pid)
        try:
            return collect(device, pid, session)
        finally:
            session.detach()
    except (AnalysisInputError, AnalysisCapabilityUnavailableError):
        raise
    except Exception as cause:
        raise _gated(
            "observe_native_calls",
            f"Frida cannot observe {target}: {cause}",
            "Grant task_for_pid permission (or run without a hardened runtime).",
        ) from cause


def observe_native_ui(process: str, *, allow_ui: bool = False) -> dict[str, Any]:
    import subprocess
    import sys

    if not allow_ui:
        raise _input("observe_native_ui", "UI observation requires --allow-ui")
    if sys.platform != "darwin":
        raise _gated(
            "observe_native_ui", "native UI observation is implemented for macOS", "Run on macOS."
        )
    script = (
        f'tell application "System Events" to tell process "{process}" '
        "to get {name, role} of every UI element of window 1"
    )
    try:
        completed = subprocess.run(
            ["osascript", "-e", script], capture_output=True, text=True, timeout=60, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as cause:
        raise _input("observe_native_ui", str(cause)) from cause
    if completed.returncode != 0:
        raise _gated(
            "observe_native_ui",
            completed.stderr.strip() or "accessibility permission is required",
            "Grant Accessibility permission to the terminal/agent.",
        )
    return {"process": process, "elements": completed.stdout.strip()}


def capture_native_ui_scenario(
    script: str,
    *,
    output: str | None = None,
    allow_ui: bool = False,
) -> dict[str, Any]:
    import subprocess
    import sys

    if not allow_ui:
        raise _input("capture_native_ui_scenario", "UI scenarios require --allow-ui")
    if sys.platform != "darwin":
        raise _gated(
            "capture_native_ui_scenario",
            "native UI scenarios are implemented for macOS",
            "Run on macOS.",
        )
    try:
        completed = subprocess.run(
            ["osascript", "-e", script], capture_output=True, text=True, timeout=120, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as cause:
        raise _input("capture_native_ui_scenario", str(cause)) from cause
    screenshot: str | None = None
    if output and completed.returncode == 0:
        destination = Path(output).expanduser()
        destination.parent.mkdir(parents=True, exist_ok=True)
        captured = subprocess.run(
            ["screencapture", "-x", str(destination)],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if captured.returncode == 0:
            screenshot = str(destination)
    if completed.returncode != 0:
        raise _gated(
            "capture_native_ui_scenario",
            completed.stderr.strip() or "accessibility permission is required",
            "Grant Accessibility permission to the terminal/agent.",
        )
    return {
        "stdout": completed.stdout.strip(),
        "screenshot": screenshot,
    }


def uninstall(config_path: str | None, skill_dir: str | None) -> dict[str, Any]:
    removed_config = False
    removed_skill = False
    if config_path:
        path = Path(config_path).expanduser()
        if path.is_file():
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except ValueError as cause:
                raise _input("uninstall", f"invalid config: {cause}") from cause
            servers = payload.get("mcpServers") if isinstance(payload, dict) else None
            if isinstance(servers, dict) and "rea-mcp" in servers:
                backup = path.with_suffix(path.suffix + ".bak")
                shutil.copy2(path, backup)
                del servers["rea-mcp"]
                path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
                removed_config = True
    if skill_dir:
        skill = Path(skill_dir).expanduser() / "reverse-engineer-anything"
        if skill.is_dir():
            shutil.rmtree(skill)
            removed_skill = True
    return {"removed_config_entry": removed_config, "removed_skill": removed_skill}


__all__ = [
    "address_to_file_offset",
    "capture_native_ui_scenario",
    "compare_application_versions",
    "compare_javascript_export_shapes",
    "compare_source_to_bundle",
    "compare_wasm_interfaces",
    "demangle_swift",
    "extract_artifact",
    "import_managed_reconstruction",
    "inspect_macho",
    "inspect_managed_native_boundaries",
    "inspect_native_dispatch_metadata",
    "inspect_signature",
    "list_architectures",
    "observe_native_calls",
    "observe_native_ui",
    "project_android_application_graph",
    "project_apple_application_graph",
    "project_harmony_application_graph",
    "project_managed_application_graph",
    "read_bytes",
    "search_bytes",
    "trace_dylib_resolution",
    "trace_javascript_semantics",
    "uninstall",
    "verify_managed_native_boundaries",
]
