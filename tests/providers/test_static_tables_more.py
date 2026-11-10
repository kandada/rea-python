from __future__ import annotations

import struct
from pathlib import Path

import pytest

from rea_mcp.domain.binary_target import parse_binary_target
from rea_mcp.providers.elf_notes import ElfNotesProvider, _gnu, _parse_range
from rea_mcp.providers.native_exports import NativeExportsProvider
from rea_mcp.providers.pe_certificates import PeCertificatesProvider
from tests.conftest import build_elf, build_pe


def _target(path: Path):
    result = parse_binary_target(path)
    assert result.ok
    return result.value


def _note(name: bytes, kind: int, desc: bytes) -> bytes:
    padded = name + b"\x00" * ((4 - len(name) % 4) % 4)
    return (
        struct.pack("<III", len(name), len(desc), kind)
        + padded
        + desc
        + b"\x00" * ((4 - len(desc) % 4) % 4)
    )


def test_elf_note_parser_decodes_gnu_notes() -> None:
    data = (
        _note(b"GNU\x00", 3, b"\xaa\xbb")
        + _note(b"GNU\x00", 1, struct.pack("<IIII", 0, 5, 10, 2))
        + _note(b"GNU\x00", 4, b"gold 1.0\x00")
    )
    entries, count = _parse_range(data, 0, len(data), "<")
    assert count == 3
    assert entries[0]["gnu"]["build_id_hex"] == "aabb"
    assert entries[1]["gnu"]["abi_tag"]["os"] == "linux"
    assert entries[2]["gnu"]["gold_version"] == "gold 1.0"


def test_elf_note_parser_rejects_out_of_bounds() -> None:
    with pytest.raises(ValueError):
        _parse_range(b"x", 0, 4, "<")
    with pytest.raises(ValueError):
        _parse_range(struct.pack("<III", 100, 0, 1), 0, 12, "<")
    assert _gnu(99, b"") is None
    assert _gnu(1, b"short")["abi_tag"]["os"] is None


def test_elf_notes_provider_no_notes(tmp_path: Path) -> None:
    path = tmp_path / "plain.elf"
    path.write_bytes(build_elf({".text": b"\x90"}))
    result = ElfNotesProvider().analyze("inspect_elf_notes", _target(path), {}, None)
    assert result.ok
    assert result.value.result["has_notes"] is False
    assert result.value.result["limitations"]


def test_elf_notes_provider_errors(tmp_path: Path) -> None:
    path = tmp_path / "bad.elf"
    path.write_bytes(b"not elf")
    assert not ElfNotesProvider().analyze("inspect_elf_notes", _target(path), {}, None).ok
    path.write_bytes(build_elf({".text": b"\x90"}))
    result = ElfNotesProvider().analyze("other", _target(path), {}, None)
    assert not result.ok


def _pe_with_security(entries: bytes, size: int | None = None) -> bytes:
    data = bytearray(build_pe())
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    directory = e_lfanew + 24 + 112 + 4 * 8
    offset = len(data)
    struct.pack_into("<II", data, directory, offset, len(entries) if size is None else size)
    return bytes(data) + entries


def test_pe_certificates_reads_entries(tmp_path: Path) -> None:
    payload = b"PKCS7"
    entry = struct.pack("<IHH", 8 + len(payload), 0x0200, 2) + payload
    path = tmp_path / "signed.exe"
    path.write_bytes(_pe_with_security(entry))
    result = PeCertificatesProvider().analyze("inspect_pe_certificates", _target(path), {}, None)
    assert result.ok, result
    assert result.value.result["has_certificate_table"] is True
    assert result.value.result["entries"][0]["type"] == 2
    assert result.value.result["entries"][0]["payload_length"] == len(payload)


def test_pe_certificates_absent_and_invalid(tmp_path: Path) -> None:
    unsigned = tmp_path / "unsigned.exe"
    unsigned.write_bytes(build_pe())
    result = PeCertificatesProvider().analyze(
        "inspect_pe_certificates", _target(unsigned), {}, None
    )
    assert result.ok
    assert result.value.result["has_certificate_table"] is False

    malformed = tmp_path / "bad.exe"
    malformed.write_bytes(_pe_with_security(struct.pack("<IHH", 100, 0, 1)))
    result = PeCertificatesProvider().analyze(
        "inspect_pe_certificates", _target(malformed), {}, None
    )
    assert not result.ok

    not_pe = tmp_path / "x.exe"
    not_pe.write_bytes(b"MZ")
    assert (
        not PeCertificatesProvider()
        .analyze("inspect_pe_certificates", _target(not_pe), {}, None)
        .ok
    )


def _pe_with_exports() -> bytes:
    data = bytearray(build_pe())
    section = 0x148
    struct.pack_into("<I", data, section + 8, 0x2000)
    struct.pack_into("<I", data, section + 16, 0x2000)
    data.extend(b"\x00" * (0x2000 - 0x200))
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    directory = e_lfanew + 24 + 112
    struct.pack_into("<II", data, directory, 0x1100, 0x100)
    text = 0x200

    def put(rva: int, payload: bytes) -> None:
        start = text + rva - 0x1000
        data[start : start + len(payload)] = payload

    put(
        0x1100,
        struct.pack(
            "<IIHHIIIIIII",
            0,
            0,
            0,
            0,
            0x11C0,
            1,
            1,
            1,
            0x1180,
            0x1188,
            0x118C,
        ),
    )
    put(0x1180, struct.pack("<I", 0x11D0))
    put(0x1188, struct.pack("<I", 0x11E0))
    put(0x118C, struct.pack("<H", 0))
    put(0x11C0, b"demo.dll\x00")
    put(0x11E0, b"DemoExport\x00")
    return bytes(data)


def test_native_exports_pe(tmp_path: Path) -> None:
    path = tmp_path / "exports.exe"
    path.write_bytes(_pe_with_exports())
    result = NativeExportsProvider().analyze("inspect_native_exports", _target(path), {}, None)
    assert result.ok, result
    assert result.value.result["dll_name"] == "demo.dll"
    assert result.value.result["exports"][0]["name"] == "DemoExport"
    assert result.value.result["exports"][0]["ordinal"] == 1


def test_native_exports_elf_absence_and_errors(tmp_path: Path) -> None:
    path = tmp_path / "plain.elf"
    path.write_bytes(build_elf({".text": b"\x90"}))
    result = NativeExportsProvider().analyze("inspect_native_exports", _target(path), {}, None)
    assert result.ok
    assert result.value.result["has_exports"] is False
    assert not NativeExportsProvider().analyze("other", _target(path), {}, None).ok
    path.write_bytes(b"not elf")
    assert not NativeExportsProvider().analyze("inspect_native_exports", _target(path), {}, None).ok
