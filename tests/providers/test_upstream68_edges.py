from __future__ import annotations

import struct
from pathlib import Path

from rea_mcp.domain.binary_target import parse_binary_target
from rea_mcp.providers.upstream68 import Upstream68Provider
from tests.conftest import build_pe


def _target(path: Path):
    result = parse_binary_target(path)
    assert result.ok
    return result.value


def _dirs_offset(data: bytes) -> int:
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    optional = e_lfanew + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    return optional + (112 if magic == 0x20B else 96)


def _large_pe() -> bytearray:
    data = bytearray(build_pe())
    section = 0x148
    struct.pack_into("<I", data, section + 8, 0x2000)
    struct.pack_into("<I", data, section + 16, 0x2000)
    data.extend(b"\x00" * (0x2000 - 0x200))
    return data


def _put(data: bytearray, rva: int, offset: int, payload: bytes) -> None:
    start = 0x200 + rva - 0x1000
    data[start + offset : start + offset + len(payload)] = payload


def _nullable(value: str) -> bytes:
    return value.encode() + b"\x00"


def test_pe_native_directories_full(tmp_path: Path) -> None:
    data = _large_pe()
    dirs = _dirs_offset(data)
    import_rva, delay_rva, tls_rva, config_rva = 0x1900, 0x1800, 0x1700, 0x1600
    struct.pack_into("<II", data, dirs + 8, import_rva, 40)
    struct.pack_into("<II", data, dirs + 13 * 8, delay_rva, 32)
    struct.pack_into("<II", data, dirs + 9 * 8, tls_rva, 40)
    struct.pack_into("<II", data, dirs + 10 * 8, config_rva, 160)

    _put(data, import_rva, 0, struct.pack("<IIIII", 0, 0, 0, 0x1940, 0x1960))
    _put(data, 0x1940, 0, _nullable("KERNEL32.dll"))
    _put(data, 0x1960, 0, struct.pack("<Q", 0x1980) + struct.pack("<Q", 0))
    _put(data, 0x1980, 0, struct.pack("<H", 7) + _nullable("ExitProcess"))

    _put(data, delay_rva, 0, struct.pack("<IIIIIIII", 1, 0x1840, 0, 0x1860, 0x1880, 0, 0, 9))
    _put(data, 0x1840, 0, _nullable("USER32.dll"))

    _put(
        data,
        tls_rva,
        0,
        struct.pack("<QQQQII", 0, 0, 0, 0x140000000 + 0x1740, 0, 0),
    )
    _put(data, 0x1740, 0, struct.pack("<Q", 0x140001010) + struct.pack("<Q", 0))

    _put(data, config_rva, 88, struct.pack("<Q", 0x140002000))
    _put(data, config_rva, 96, struct.pack("<Q", 0x140003000))
    _put(data, config_rva, 104, struct.pack("<Q", 2))
    _put(data, config_rva, 128, struct.pack("<Q", 0x140004000))
    _put(data, config_rva, 136, struct.pack("<Q", 3))
    _put(data, config_rva, 144, struct.pack("<I", 0x500))

    path = tmp_path / "full.exe"
    path.write_bytes(data)
    provider = Upstream68Provider()
    result = provider.analyze("inspect_pe_native_metadata", _target(path), {}, None)
    assert result.ok, result
    payload = result.value.result
    assert payload["imports"][0]["dll"] == "KERNEL32.dll"
    assert payload["imports"][0]["functions"][0]["name"] == "ExitProcess"
    assert payload["delay_imports"][0]["dll"] == "USER32.dll"
    assert payload["tls"]["callbacks"] == ["0x140001010"]
    assert payload["load_config"]["guard_flags"] == 0x500


def test_pe_native_metadata_rejects_non_pe(tmp_path: Path) -> None:
    path = tmp_path / "not.exe"
    path.write_bytes(b"not a pe")
    result = Upstream68Provider().analyze("inspect_pe_native_metadata", _target(path), {}, None)
    assert not result.ok
    assert "not a PE" in result.error.message


def test_dol_and_fdt_reject_malformed(tmp_path: Path) -> None:
    provider = Upstream68Provider()
    dol = tmp_path / "short.dol"
    dol.write_bytes(b"\x00" * 16)
    result = provider.analyze("inspect_dol_executable", _target(dol), {}, None)
    assert not result.ok
    assert "truncated" in result.error.message

    bad_fdt = tmp_path / "bad.dtb"
    bad_fdt.write_bytes(b"NO")
    result = provider.analyze("inspect_flattened_devicetree", _target(bad_fdt), {}, None)
    assert not result.ok
    assert "flattened device tree" in result.error.message

    outside = tmp_path / "outside.dtb"
    outside.write_bytes(struct.pack(">10I", 0xD00DFEED, 1000, 40, 40, 0, 17, 16, 0, 100, 100))
    result = provider.analyze("inspect_flattened_devicetree", _target(outside), {}, None)
    assert not result.ok
    assert "outside the file" in result.error.message


def test_protobuf_wire_types_and_grpc(tmp_path: Path) -> None:
    body = (
        b"\x08\x96\x01"
        + b"\x11"
        + bytes(range(8))
        + b"\x1a\x03hey"
        + b"\x25"
        + b"\x01\x02\x03\x04"
        + b"\x3a\x04\xde\xad\xbe\xef"
    )
    framed = b"\x00" + len(body).to_bytes(4, "big") + body
    path = tmp_path / "body.pb"
    path.write_bytes(framed)
    result = Upstream68Provider().analyze("inspect_protobuf_body", _target(path), {}, None)
    assert result.ok
    payload = result.value.result
    assert payload["grpc"]["message_length"] == len(body)
    assert payload["fields"][0]["value"] == 150
    assert payload["fields"][1]["wire"] == "fixed64"
    assert payload["fields"][2]["text"] == "hey"
    assert payload["fields"][3]["wire"] == "fixed32"


def test_protobuf_truncated_payload(tmp_path: Path) -> None:
    path = tmp_path / "bad.pb"
    path.write_bytes(b"\x0a\x05abc")
    result = Upstream68Provider().analyze("inspect_protobuf_body", _target(path), {}, None)
    assert result.ok
    assert result.value.result["truncated"] is True


def _pyinstaller_toc() -> bytes:
    name = b"main.py\0"
    entry = struct.pack(">I", 18 + len(name)) + struct.pack(">IIIBc", 0, 10, 20, 1, b"m") + name
    toc = entry
    cookie = struct.pack(
        ">8sIIII64s",
        b"MEI\014\013\012\013\016",
        len(toc),
        0,
        len(toc),
        312,
        b"python312.dll",
    )
    return toc + cookie


def test_pyinstaller_toc_entries(tmp_path: Path) -> None:
    path = tmp_path / "app.bin"
    path.write_bytes(_pyinstaller_toc())
    result = Upstream68Provider().analyze("inspect_packaged_application", _target(path), {}, None)
    assert result.ok
    archive = result.value.result["pyinstaller"]
    assert archive["entries"][0]["name"] == "main.py"
    assert archive["entries"][0]["type"] == "m"
    assert archive["py_version"] == 312


def test_packaged_invalid_ips_and_truncated_sea(tmp_path: Path) -> None:
    bad = tmp_path / "bad.ips"
    bad.write_text("{not json", encoding="utf-8")
    result = Upstream68Provider().analyze("inspect_packaged_application", _target(bad), {}, None)
    assert result.ok
    assert result.value.result["ips"] is None

    sea = tmp_path / "sea.exe"
    sea.write_bytes(b"xxNODE_SEA_BLOB" + b"tail")
    result = Upstream68Provider().analyze("inspect_packaged_application", _target(sea), {}, None)
    assert result.ok
    assert result.value.result["node_sea"]["marker_offset"] == 2
    assert "blob_size" not in result.value.result["node_sea"]


def test_upstream_supports_and_errors(tmp_path: Path) -> None:
    provider = Upstream68Provider()
    for name in ("a.dol", "a.pb", "a.txt"):
        (tmp_path / name).write_bytes(b"x")
    assert provider.supports(_target(tmp_path / "a.dol")).status == "supported"
    assert provider.supports(_target(tmp_path / "a.pb")).status == "supported"
    unknown = tmp_path / "a.txt"
    assert provider.supports(_target(unknown)).status == "supported"

    missing = tmp_path / "missing.bin"
    missing.write_bytes(b"x")
    missing_target = _target(missing)
    missing.unlink()
    result = provider.analyze("inspect_dol_executable", missing_target, {}, None)
    assert not result.ok

    path = tmp_path / "x.bin"
    path.write_bytes(b"")
    result = provider.analyze("not_an_operation", _target(path), {}, None)
    assert not result.ok
    assert "unsupported operation" in result.error.message


def test_fdt_disassembly_missing_file_is_empty(tmp_path: Path) -> None:
    from tests.providers.test_upstream68 import _fdt

    path = tmp_path / "board.dtb"
    path.write_bytes(_fdt())
    result = Upstream68Provider().analyze(
        "inspect_flattened_devicetree",
        _target(path),
        {"disassembly": str(tmp_path / "missing.txt")},
        None,
    )
    assert result.ok
    assert result.value.result["mmio_attributed"] == []
