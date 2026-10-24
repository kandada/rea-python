"""Compare typed WASM import/export declarations without executing modules."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def _uleb(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
        if shift > 63:
            raise ValueError("WASM LEB128 is too large")
    raise ValueError("truncated WASM LEB128")


def _string(data: bytes, offset: int) -> tuple[str, int]:
    length, offset = _uleb(data, offset)
    if offset + length > len(data):
        raise ValueError("truncated WASM string")
    return data[offset : offset + length].decode("utf-8", errors="replace"), offset + length


def _interfaces(data: bytes) -> dict[str, dict[str, Any]]:
    if data[:4] != b"\x00asm":
        raise ValueError("not a WASM module")
    offset = 8
    imports: dict[str, Any] = {}
    exports: dict[str, Any] = {}
    while offset < len(data):
        section = data[offset]
        offset += 1
        size, offset = _uleb(data, offset)
        end = offset + size
        if end > len(data):
            raise ValueError("WASM section is truncated")
        if section == 2:
            count, cursor = _uleb(data, offset)
            for _ in range(min(count, 10000)):
                module, cursor = _string(data, cursor)
                name, cursor = _string(data, cursor)
                kind = data[cursor : cursor + 1]
                cursor += 1
                if kind == b"\x00":
                    _, cursor = _uleb(data, cursor)
                elif kind == b"\x01":
                    cursor += 1
                    flags = data[cursor : cursor + 1]
                    cursor += 1
                    _, cursor = _uleb(data, cursor)
                    if flags and flags[0] & 1:
                        _, cursor = _uleb(data, cursor)
                elif kind == b"\x02":
                    flags = data[cursor : cursor + 1]
                    cursor += 1
                    _, cursor = _uleb(data, cursor)
                    if flags and flags[0] & 1:
                        _, cursor = _uleb(data, cursor)
                elif kind == b"\x03":
                    cursor += 2
                imports[f"{module}.{name}"] = {"module": module, "name": name, "kind": kind.hex()}
        elif section == 7:
            count, cursor = _uleb(data, offset)
            for _ in range(min(count, 10000)):
                name, cursor = _string(data, cursor)
                kind = data[cursor : cursor + 1]
                cursor += 1
                index, cursor = _uleb(data, cursor)
                exports[name] = {"name": name, "kind": kind.hex(), "index": index}
        offset = end
    return {"imports": imports, "exports": exports}


def compare_wasm_interfaces(left: str, right: str, selection: str = "both") -> dict[str, Any]:
    if selection not in ("both", "imports", "exports"):
        raise ValueError("selection must be both, imports or exports")
    left_data = Path(left).read_bytes()
    right_data = Path(right).read_bytes()
    left_interface = _interfaces(left_data)
    right_interface = _interfaces(right_data)
    result: dict[str, Any] = {"selection": selection, "status": "unchanged"}
    changed = False
    for collection in ("imports", "exports") if selection == "both" else (selection,):
        left_rows = left_interface[collection]
        right_rows = right_interface[collection]
        added = sorted(right_rows.keys() - left_rows.keys())
        removed = sorted(left_rows.keys() - right_rows.keys())
        modified = sorted(
            key for key in left_rows.keys() & right_rows.keys() if left_rows[key] != right_rows[key]
        )
        result[collection] = {
            "added": added[:500],
            "removed": removed[:500],
            "modified": modified[:500],
            "added_count": len(added),
            "removed_count": len(removed),
            "modified_count": len(modified),
            "truncated": any(len(items) > 500 for items in (added, removed, modified)),
        }
        changed = changed or bool(added or removed or modified)
    result["status"] = "changed" if changed else "unchanged"
    result["limitations"] = [
        "Names, kinds and indices are compared; full WASM type signatures are not decoded.",
    ]
    return result


__all__ = ["compare_wasm_interfaces"]
