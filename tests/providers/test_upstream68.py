from __future__ import annotations

import json
import struct
from pathlib import Path

from rea_mcp.domain.binary_target import parse_binary_target
from rea_mcp.providers.upstream68 import Upstream68Provider


def _target(path: Path):
    result = parse_binary_target(path)
    assert result.ok
    return result.value


def _dol() -> bytes:
    header = bytearray(0x100)
    struct.pack_into(">I", header, 0x00, 0x100)
    struct.pack_into(">I", header, 0x48, 0x80000000)
    struct.pack_into(">I", header, 0xE0, 0x80000000)
    return bytes(header) + b"\x90" * 16


def _fdt() -> bytes:
    strings = b"compatible\0reg\0"
    reg_offset = len(b"compatible\0")
    struct_data = b"".join(
        [
            struct.pack(">I", 1) + b"\0",
            struct.pack(">III", 3, 4, 0) + b"test",
            struct.pack(">III", 3, 8, reg_offset)
            + (0x1000).to_bytes(4, "big")
            + (0x100).to_bytes(4, "big"),
            struct.pack(">I", 2),
            struct.pack(">I", 9),
        ]
    )
    total = 40 + len(struct_data) + len(strings)
    header = struct.pack(
        ">10I",
        0xD00DFEED,
        total,
        40,
        40 + len(struct_data),
        0,
        17,
        16,
        0,
        len(strings),
        len(struct_data),
    )
    return header + struct_data + strings


def test_dol_fdt_protobuf_and_packaged(tmp_path: Path) -> None:
    provider = Upstream68Provider()
    dol = tmp_path / "game.dol"
    dol.write_bytes(_dol())
    result = provider.analyze("inspect_dol_executable", _target(dol), {}, None)
    assert result.ok
    assert result.value.result["entry"] == "0x80000000"

    fdt = tmp_path / "board.dtb"
    fdt.write_bytes(_fdt())
    result = provider.analyze("inspect_flattened_devicetree", _target(fdt), {}, None)
    assert result.ok
    assert result.value.result["node_count"] >= 1
    assert result.value.result["mmio_candidates"]
    disassembly = tmp_path / "disasm.txt"
    disassembly.write_text("1000: ldr r0, [0x1000]\n", encoding="utf-8")
    result = provider.analyze(
        "inspect_flattened_devicetree",
        _target(fdt),
        {"disassembly": str(disassembly)},
        None,
    )
    assert result.ok
    assert result.value.result["mmio_attributed"]

    proto = tmp_path / "body.pb"
    proto.write_bytes(b"\x08\x07\x12\x02hi")
    result = provider.analyze("inspect_protobuf_body", _target(proto), {}, None)
    assert result.ok
    assert result.value.result["fields"][0]["value"] == 7
    assert result.value.result["fields"][1]["text"] == "hi"

    packaged = tmp_path / "app.bin"
    packaged.write_bytes(b"prefix" + b"MEI\014\013\012\013\016" + b"suffix")
    result = provider.analyze("inspect_packaged_application", _target(packaged), {}, None)
    assert result.ok
    assert result.value.result["pyinstaller"]["cookie_offset"] >= 0


def test_packaged_ips(tmp_path: Path) -> None:
    path = tmp_path / "crash.ips"
    path.write_text(
        json.dumps({"bug_type": "309", "name": "Demo", "exception": {"type": "EXC"}}),
        encoding="utf-8",
    )
    result = Upstream68Provider().analyze("inspect_packaged_application", _target(path), {}, None)
    assert result.ok
    assert result.value.result["ips"]["bug_type"] == "309"


def test_pe_native_metadata_reader(pe_clr_file: Path) -> None:
    result = Upstream68Provider().analyze(
        "inspect_pe_native_metadata", _target(pe_clr_file), {}, None
    )
    assert result.ok
    assert "imports" in result.value.result
    assert "load_config" in result.value.result


def test_node_sea_note_blob(tmp_path: Path) -> None:
    name = b"NODE_SEA_BLOB"
    payload = b"\x01\x02\x03\x04"
    note = (
        struct.pack("<III", len(name) + 1, len(payload), 1)
        + name
        + b"\0"
        + b"\0" * ((4 - (len(name) + 1) % 4) % 4)
        + payload
    )
    path = tmp_path / "sea.exe"
    path.write_bytes(b"prefix" + note)
    result = Upstream68Provider().analyze("inspect_packaged_application", _target(path), {}, None)
    assert result.ok
    sea = result.value.result["node_sea"]
    assert sea["blob_size"] == len(payload)
    assert sea["sha256"]
