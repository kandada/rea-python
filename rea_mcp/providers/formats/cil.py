"""Minimal CIL (Common Intermediate Language) method-body decoder.

Parses a managed method body (tiny/fat header) and disassembles a bounded set of
IL opcodes. Operand values are reported (tokens, branches, immediates); token
resolution to member names is out of scope.
"""

from __future__ import annotations

import mmap
from typing import Any

# opcode -> (name, operand kind)
_OPCODES: dict[int, tuple[str, str]] = {
    0x00: ("nop", ""),
    0x01: ("break", ""),
    0x02: ("ldarg.0", ""),
    0x03: ("ldarg.1", ""),
    0x04: ("ldarg.2", ""),
    0x05: ("ldarg.3", ""),
    0x06: ("ldloc.0", ""),
    0x07: ("ldloc.1", ""),
    0x08: ("ldloc.2", ""),
    0x09: ("ldloc.3", ""),
    0x0A: ("stloc.0", ""),
    0x0B: ("stloc.1", ""),
    0x0C: ("stloc.2", ""),
    0x0D: ("stloc.3", ""),
    0x0E: ("ldarg.s", "u1"),
    0x10: ("starg.s", "u1"),
    0x11: ("ldloc.s", "u1"),
    0x12: ("ldloca.s", "u1"),
    0x13: ("stloc.s", "u1"),
    0x14: ("ldnull", ""),
    0x15: ("ldc.i4.m1", ""),
    0x16: ("ldc.i4.0", ""),
    0x17: ("ldc.i4.1", ""),
    0x18: ("ldc.i4.2", ""),
    0x19: ("ldc.i4.3", ""),
    0x1A: ("ldc.i4.4", ""),
    0x1B: ("ldc.i4.5", ""),
    0x1C: ("ldc.i4.6", ""),
    0x1D: ("ldc.i4.7", ""),
    0x1E: ("ldc.i4.8", ""),
    0x1F: ("ldc.i4.s", "i1"),
    0x20: ("ldc.i4", "i4"),
    0x21: ("ldc.i8", "i8"),
    0x22: ("ldc.r4", "r4"),
    0x23: ("ldc.r8", "r8"),
    0x25: ("dup", ""),
    0x26: ("pop", ""),
    0x27: ("jmp", "token"),
    0x28: ("call", "token"),
    0x29: ("calli", "token"),
    0x2A: ("ret", ""),
    0x2B: ("br.s", "i1"),
    0x2C: ("brfalse.s", "i1"),
    0x2D: ("brtrue.s", "i1"),
    0x2E: ("beq.s", "i1"),
    0x2F: ("bge.s", "i1"),
    0x30: ("bgt.s", "i1"),
    0x31: ("ble.s", "i1"),
    0x32: ("blt.s", "i1"),
    0x33: ("bne.un.s", "i1"),
    0x38: ("br", "i4"),
    0x39: ("brfalse", "i4"),
    0x3A: ("brtrue", "i4"),
    0x3B: ("beq", "i4"),
    0x3C: ("bge", "i4"),
    0x3D: ("bgt", "i4"),
    0x3E: ("ble", "i4"),
    0x3F: ("blt", "i4"),
    0x45: ("switch", "switch"),
    0x46: ("ldind.i1", ""),
    0x47: ("ldind.u1", ""),
    0x48: ("ldind.i2", ""),
    0x49: ("ldind.u2", ""),
    0x4A: ("ldind.i4", ""),
    0x4B: ("ldind.u4", ""),
    0x4C: ("ldind.i8", ""),
    0x4D: ("ldind.i", ""),
    0x4E: ("ldind.r4", ""),
    0x4F: ("ldind.r8", ""),
    0x50: ("stind.ref", ""),
    0x51: ("stind.i1", ""),
    0x52: ("stind.i2", ""),
    0x53: ("stind.i4", ""),
    0x54: ("stind.i8", ""),
    0x55: ("stind.r4", ""),
    0x56: ("stind.r8", ""),
    0x57: ("add", ""),
    0x58: ("sub", ""),
    0x59: ("mul", ""),
    0x5A: ("div", ""),
    0x5B: ("div.un", ""),
    0x5C: ("rem", ""),
    0x5D: ("rem.un", ""),
    0x5E: ("and", ""),
    0x5F: ("or", ""),
    0x60: ("xor", ""),
    0x61: ("shl", ""),
    0x62: ("shr", ""),
    0x63: ("shr.un", ""),
    0x64: ("neg", ""),
    0x65: ("not", ""),
    0x66: ("conv.i1", ""),
    0x67: ("conv.i2", ""),
    0x68: ("conv.i4", ""),
    0x69: ("conv.i8", ""),
    0x6A: ("conv.r4", ""),
    0x6B: ("conv.r8", ""),
    0x6C: ("conv.u4", ""),
    0x6D: ("conv.u8", ""),
    0x6F: ("callvirt", "token"),
    0x70: ("cpobj", "token"),
    0x71: ("ldobj", "token"),
    0x72: ("ldstr", "token"),
    0x73: ("newobj", "token"),
    0x74: ("castclass", "token"),
    0x75: ("isinst", "token"),
    0x79: ("unbox", "token"),
    0x7A: ("throw", ""),
    0x7B: ("ldfld", "token"),
    0x7C: ("ldflda", "token"),
    0x7D: ("stfld", "token"),
    0x7E: ("ldsfld", "token"),
    0x7F: ("ldsflda", "token"),
    0x80: ("stsfld", "token"),
    0x81: ("stobj", "token"),
    0x8C: ("box", "token"),
    0x8D: ("newarr", "token"),
    0x8E: ("ldlen", ""),
    0x8F: ("ldelema", "token"),
    0x90: ("ldelem.i1", ""),
    0x91: ("ldelem.u1", ""),
    0x92: ("ldelem.i2", ""),
    0x93: ("ldelem.u2", ""),
    0x94: ("ldelem.i4", ""),
    0x95: ("ldelem.u4", ""),
    0x96: ("ldelem.i8", ""),
    0x97: ("ldelem.i", ""),
    0xA2: ("stelem.i", ""),
    0xA3: ("stelem.i1", ""),
    0xA4: ("stelem.i2", ""),
    0xA5: ("stelem.i4", ""),
    0xA6: ("stelem.i8", ""),
    0xD0: ("ldtoken", "token"),
    0xDD: ("leave", "i4"),
    0xDE: ("leave.s", "i1"),
    0xFF: ("no-op", ""),
}

_TWO_BYTE: dict[int, tuple[str, str]] = {
    0x01: ("ceq", ""),
    0x02: ("cgt", ""),
    0x03: ("cgt.un", ""),
    0x04: ("clt", ""),
    0x05: ("clt.un", ""),
    0x06: ("ldftn", "token"),
    0x07: ("ldvirtftn", "token"),
    0x09: ("ldarg", "u2"),
    0x0A: ("ldarga", "u2"),
    0x0B: ("starg", "u2"),
    0x0C: ("ldloc", "u2"),
    0x0D: ("ldloca", "u2"),
    0x0E: ("stloc", "u2"),
    0x15: ("initobj", "token"),
    0x16: ("constrained.", "token"),
    0x1C: ("sizeof", "token"),
    0x1D: ("refanytype", ""),
    0x1E: ("readonly.", ""),
}

_MAX_INSTRUCTIONS = 2000


class CilError(ValueError):
    pass


def parse_method_body(data: bytes | mmap.mmap, offset: int) -> tuple[dict[str, Any], bytes]:
    if offset < 0 or offset >= len(data):
        raise CilError("Method body is outside the image")
    first = data[offset]
    if first & 0x03 == 0x02:  # tiny
        code_size = first >> 2
        return {"format": "tiny"}, data[offset + 1 : offset + 1 + code_size]
    if first & 0x03 == 0x03:  # fat
        flags = int.from_bytes(data[offset : offset + 2], "little")
        header_size = (flags >> 12) * 4
        max_stack = int.from_bytes(data[offset + 2 : offset + 4], "little")
        code_size = int.from_bytes(data[offset + 4 : offset + 8], "little")
        code_offset = offset + max(header_size, 12)
        return (
            {"format": "fat", "max_stack": max_stack, "header_size": header_size},
            data[code_offset : code_offset + code_size],
        )
    raise CilError("Unrecognized method body header")


def disassemble(code: bytes) -> list[dict[str, Any]]:
    instructions: list[dict[str, Any]] = []
    offset = 0
    while offset < len(code) and len(instructions) < _MAX_INSTRUCTIONS:
        start = offset
        byte = code[offset]
        offset += 1
        if byte == 0xFE:
            if offset >= len(code):
                instructions.append({"offset": start, "opcode": "prefix.fe", "operand": None})
                break
            second = code[offset]
            offset += 1
            name, kind = _TWO_BYTE.get(second, (f"fe.{second:02x}", ""))
        else:
            name, kind = _OPCODES.get(byte, (f"unk.{byte:02x}", ""))
        operand, offset = _read_operand(code, offset, kind)
        instructions.append({"offset": start, "opcode": name, "operand": operand})
    return instructions


def _read_operand(code: bytes, offset: int, kind: str) -> tuple[Any, int]:
    if kind == "":
        return None, offset
    if kind == "u1":
        return code[offset], offset + 1
    if kind == "i1":
        value = int.from_bytes(code[offset : offset + 1], "little", signed=True)
        return value, offset + 1
    if kind == "u2":
        return int.from_bytes(code[offset : offset + 2], "little"), offset + 2
    if kind == "i4":
        return int.from_bytes(code[offset : offset + 4], "little", signed=True), offset + 4
    if kind == "token":
        return f"0x{int.from_bytes(code[offset : offset + 4], 'little'):08x}", offset + 4
    if kind == "i8":
        return int.from_bytes(code[offset : offset + 8], "little", signed=True), offset + 8
    if kind == "r4":
        import struct

        return struct.unpack_from("<f", code, offset)[0], offset + 4
    if kind == "r8":
        import struct

        return struct.unpack_from("<d", code, offset)[0], offset + 8
    if kind == "switch":
        count = int.from_bytes(code[offset : offset + 4], "little")
        offset += 4
        targets = [
            int.from_bytes(code[offset + i * 4 : offset + i * 4 + 4], "little", signed=True)
            for i in range(count)
        ]
        return {"count": count, "targets": targets[:64]}, offset + count * 4
    return None, offset


__all__ = ["CilError", "disassemble", "parse_method_body"]
