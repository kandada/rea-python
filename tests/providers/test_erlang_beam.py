from __future__ import annotations

import struct
from pathlib import Path

from rea_mcp.domain.binary_target import parse_binary_target
from rea_mcp.providers.erlang_beam import ErlangBeamProvider


def _chunk(name: bytes, payload: bytes) -> bytes:
    return name + struct.pack(">I", len(payload)) + payload + (b"\x00" if len(payload) % 2 else b"")


def _beam() -> bytes:
    atoms = struct.pack("<I", 3) + b"\x03app\x03run\x03ext"
    exports = struct.pack("<IIII", 2, 0, 1, 16)
    imports = struct.pack("<III", 3, 2, 0)
    code = struct.pack("<IIIII", 20, 1, 200, 2, 1) + b"\x00" * 8
    body = (
        _chunk(b"AtU8", atoms)
        + _chunk(b"ExpT", exports)
        + _chunk(b"ImpT", imports)
        + _chunk(b"Code", code)
    )
    return b"FOR1" + struct.pack(">I", len(body) + 4) + b"BEAM" + body


def _target(path: Path):  # type: ignore[no-untyped-def]
    parsed = parse_binary_target(str(path))
    assert parsed.ok
    return parsed.value


def test_erlang_beam_chunks_atoms_and_exports(tmp_path: Path) -> None:
    path = tmp_path / "app.beam"
    path.write_bytes(_beam())
    result = ErlangBeamProvider().analyze("inspect_erlang_beam", _target(path), {}, None)
    assert result.ok
    data = result.value.result
    assert data["module"] == "app"
    assert data["atoms"] == ["app", "run", "ext"]
    assert data["exports"][0]["function"] == "run"
    assert data["imports"][0]["module"] == "ext"
    assert data["code"]["label_count"] == 2

    invalid = tmp_path / "bad.beam"
    invalid.write_bytes(b"not a beam")
    assert not ErlangBeamProvider().analyze("inspect_erlang_beam", _target(invalid), {}, None).ok
