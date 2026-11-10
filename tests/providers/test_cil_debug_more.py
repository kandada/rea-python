from __future__ import annotations

import struct
from pathlib import Path

import pytest

from rea_mcp.domain.binary_target import parse_binary_target
from rea_mcp.providers.debug_sessions import DebugSessionProvider
from rea_mcp.providers.formats.cil import CilError, disassemble, parse_method_body


def _target(path: Path):
    result = parse_binary_target(path)
    assert result.ok
    return result.value


def test_cil_tiny_body_and_operands() -> None:
    code = bytes([0x17, 0x2A])
    body = bytes([(len(code) << 2) | 0x02]) + code
    header, extracted = parse_method_body(body, 0)
    assert header == {"format": "tiny"}
    assert extracted == code
    instructions = disassemble(
        bytes(
            [
                0x00,
                0x1F,
                0xFF,
                0x28,
                0x78,
                0x56,
                0x34,
                0x12,
                0xFE,
                0x01,
                0x45,
                0x02,
                0x00,
                0x00,
                0x00,
                0x05,
                0x00,
                0x00,
                0x00,
                0xFF,
                0x00,
            ]
        )
    )
    assert [item["opcode"] for item in instructions[:4]] == ["nop", "ldc.i4.s", "call", "ceq"]
    assert instructions[1]["operand"] == -1
    assert instructions[2]["operand"] == "0x12345678"
    assert instructions[3]["operand"] is None
    assert instructions[4]["operand"] == {"count": 2, "targets": [5, 255]}


def test_cil_fat_body_and_errors() -> None:
    flags = (3 << 12) | 0x03
    header = struct.pack("<HHII", flags, 8, 1, 0x11000001)
    body = header + b"\x2a"
    parsed, code = parse_method_body(body, 0)
    assert parsed["format"] == "fat"
    assert parsed["max_stack"] == 8
    assert code == b"\x2a"
    with pytest.raises(CilError):
        parse_method_body(b"", 0)
    with pytest.raises(CilError):
        parse_method_body(b"\x00\x00\x00\x00", 0)
    with pytest.raises(CilError):
        parse_method_body(b"\x00", 5)


def test_cil_disassembly_bounds() -> None:
    assert disassemble(b"") == []
    assert disassemble(b"\xfe")[0]["opcode"] == "prefix.fe"
    assert disassemble(b"\xff")[0]["opcode"] == "no-op"
    assert disassemble(b"\xfe\xff")[0]["opcode"] == "fe.ff"


def test_debug_provider_unavailable_and_unknown(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "x.bin"
    target.write_bytes(b"x")
    provider = DebugSessionProvider()
    assert provider.supports(_target(target)).status == "supported"
    result = provider.analyze("not_a_debug_op", _target(target), {}, None)
    assert not result.ok
    assert "unsupported operation" in result.error.message

    import rea_mcp.providers.debug_sessions as sessions

    monkeypatch.setattr(
        sessions,
        "resolve_tool",
        lambda *args, **kwargs: sessions.ToolResolution(False, None, "missing engine"),
    )
    monkeypatch.setattr(sessions, "optional_import", lambda name: None)
    for operation in ("start_gdb_session", "start_rizin_debug_session", "list_cutter_sessions"):
        result = provider.analyze(operation, _target(target), {}, None)
        assert not result.ok
        assert result.error.reason == "provider_unavailable"


def test_debug_cutter_socket_detection(tmp_path: Path, monkeypatch) -> None:
    provider = DebugSessionProvider()
    monkeypatch.delenv("REA_CUTTER_BRIDGE", raising=False)
    assert provider._cutter().available is False
    sock = tmp_path / "cutter.sock"
    monkeypatch.setenv("REA_CUTTER_BRIDGE", str(sock))
    assert provider._cutter().available is False
    sock.write_bytes(b"")
    assert provider._cutter().available is True
    assert provider._availability_for("list_cutter_sessions") == (True, None)
