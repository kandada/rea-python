from __future__ import annotations

from pathlib import Path

from rea_mcp.application.wasm_compare import compare_wasm_interfaces


def _uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(payload)) + payload


def _module(exports: list[str]) -> bytes:
    imports = b"\x01" + b"\x03env\x01f\x00\x00"
    export_payload = _uleb(len(exports))
    for index, name in enumerate(exports):
        export_payload += _uleb(len(name)) + name.encode() + b"\x00" + _uleb(index)
    return b"\x00asm\x01\x00\x00\x00" + _section(2, imports) + _section(7, export_payload)


def test_compare_wasm_interfaces(tmp_path: Path) -> None:
    left = tmp_path / "left.wasm"
    right = tmp_path / "right.wasm"
    left.write_bytes(_module(["run"]))
    right.write_bytes(_module(["run", "stop"]))
    result = compare_wasm_interfaces(str(left), str(right))
    assert result["status"] == "changed"
    assert result["exports"]["added"] == ["stop"]
