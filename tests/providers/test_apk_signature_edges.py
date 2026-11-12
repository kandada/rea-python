from __future__ import annotations

import struct
import zipfile
from pathlib import Path

from rea_mcp.domain.binary_target import parse_binary_target
from rea_mcp.providers.apk_signature import (
    _ROTATION,
    _STAMP_V2,
    _V2,
    ApkSignatureProvider,
    _algorithm_records,
    _chunk,
    _inspect,
    _rotation,
    _signing_block,
    _source_stamp,
)


def _target(path: Path):
    result = parse_binary_target(path)
    assert result.ok
    return result.value


def _chunked(value: bytes) -> bytes:
    return struct.pack("<I", len(value)) + value


def _pair(identifier: int, value: bytes) -> bytes:
    return struct.pack("<Q", 4 + len(value)) + struct.pack("<I", identifier) + value


def _with_block(pairs: bytes) -> bytes:
    import io

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("classes.dex", b"dex")
    data = buffer.getvalue()
    eocd = data.rfind(b"PK\x05\x06")
    central = struct.unpack_from("<I", data, eocd + 16)[0]
    size = len(pairs) + 24
    block = struct.pack("<Q", size) + pairs + struct.pack("<Q", size) + b"APK Sig Block 42"
    updated = bytearray(data[:central] + block + data[central:])
    struct.pack_into("<I", updated, eocd + len(block) + 16, central + len(block))
    return bytes(updated)


def test_signing_block_v2_and_source_stamp(tmp_path: Path) -> None:
    stamp_cert = b"stamp-cert"
    stamp = _chunked(_chunked(stamp_cert))
    data = _with_block(_pair(_V2, struct.pack("<I", 0)) + _pair(_STAMP_V2, stamp))
    path = tmp_path / "signed.apk"
    path.write_bytes(data)
    result = ApkSignatureProvider().analyze("inspect_apk_signature", _target(path), {}, None)
    assert result.ok
    payload = result.value.result
    assert payload["has_signatures"] is True
    assert payload["scheme_count"] == 1
    assert payload["schemes"][0]["scheme"] == "v2"
    assert payload["schemes"][0]["signer_count"] == 0
    assert payload["source_stamp"]["present"] is True
    assert payload["source_stamp"]["certificate"]["der_length"] == len(stamp_cert)


def test_signing_block_helpers_and_errors(tmp_path: Path) -> None:
    assert _chunk(b"\x03\x00\x00\x00abc", 0) == (b"abc", 7)
    assert _chunk(b"\x05\x00\x00\x00ab", 0) is None
    records, cursor = _algorithm_records(_chunked(struct.pack("<I", 0x0101) + _chunked(b"sig")), 0)
    assert records == [(0x0101, b"sig")]
    assert cursor == len(_chunked(struct.pack("<I", 0x0101) + _chunked(b"sig")))

    malformed = tmp_path / "bad.apk"
    malformed.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    assert _signing_block(malformed.read_bytes()) is None


def test_rotation_attribute() -> None:
    cert = b"old-cert"
    node = _chunked(_chunked(cert)) + struct.pack("<I", 24)
    value = struct.pack("<I", 1) + _chunked(node)
    rotation = _rotation([{"id": _ROTATION, "value": value}])
    assert rotation["present"] is True
    assert rotation["lineage"][0]["flags"] == 24
    assert rotation["lineage"][0]["capabilities"]["rollback"] is True
    assert rotation["lineage"][0]["capabilities"]["auth"] is True
    assert rotation["lineage"][0]["capabilities"]["installed_data"] is False
    assert _rotation([{"id": _ROTATION, "value": b"\x00"}])["decode_error"]
    assert _rotation([{"id": _ROTATION, "value": struct.pack("<I", 9)}])["decode_error"]


def test_source_stamp_edge_cases() -> None:
    assert _source_stamp(None)["present"] is False
    assert _source_stamp({_STAMP_V2: b"\x05"})["decode_error"]
    assert _source_stamp({_STAMP_V2: _chunked(b"\x05")})["decode_error"]


def test_inspect_without_block() -> None:
    import io

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("classes.dex", b"dex")
    result = _inspect(buffer.getvalue())
    assert result["has_signatures"] is False
    assert result["v1"]["present"] is False
    assert result["scheme_count"] == 0
    assert result["posture"]["self_consistent"] is True
