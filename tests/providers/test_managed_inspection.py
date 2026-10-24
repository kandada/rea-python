from __future__ import annotations

import struct
from pathlib import Path

from rea_mcp.domain.binary_target import parse_binary_target
from rea_mcp.providers.dotnet import ManagedStaticProvider
from rea_mcp.providers.formats.managed_inspection import summarize_managed_inspection
from tests.conftest import _pad4, build_pe


def _blob_item(payload: bytes) -> bytes:
    assert len(payload) < 0x80
    return bytes([len(payload)]) + payload


def _metadata_blob(
    *,
    stream_name: str = "#~",
    extra_data: bytes | None = None,
    method_rva: int = 0,
    user_string: str | None = None,
    constant: str = "literal",
) -> bytes:
    strings = bytearray(b"\x00")
    indexes: dict[str, int] = {}

    def string(value: str) -> int:
        if value not in indexes:
            indexes[value] = len(strings)
            strings.extend(value.encode() + b"\x00")
        return indexes[value]

    namespace = string("Example")
    outer = string("Outer")
    inner = string("Inner")
    field = string("Value")
    method = string("Run")

    blobs = bytearray(b"\x00")
    blob_indexes: dict[bytes, int] = {}

    def blob(value: bytes) -> int:
        if value not in blob_indexes:
            blob_indexes[value] = len(blobs)
            blobs.extend(_blob_item(value))
        return blob_indexes[value]

    field_signature = blob(bytes([0x06, 0x0E]))  # string
    method_signature = blob(bytes([0x00, 0x00, 0x01]))  # void Run()
    constant_value = constant.encode("utf-16-le")
    constant_blob = blob(constant_value)

    valid = (1 << 0x02) | (1 << 0x04) | (1 << 0x06) | (1 << 0x0B) | (1 << 0x29)
    tables = bytearray()
    tables += struct.pack("<I", 0)
    tables += struct.pack("<BBBB", 2, 0, 0, 1)
    tables += struct.pack("<Q", valid)
    tables += struct.pack("<Q", 0)
    for count in (2, 1, 1, 1, 1):
        tables += struct.pack("<I", count)
    if extra_data is not None:
        tables += extra_data
    # TypeDef rows: Outer has one field and one method; Inner is nested only.
    tables += struct.pack("<IHHHHH", 0, outer, namespace, 0, 1, 1)
    tables += struct.pack("<IHHHHH", 0, inner, 0, 0, 2, 2)
    # Field / MethodDef / Constant / NestedClass rows.
    tables += struct.pack("<HHH", 0, field, field_signature)
    tables += struct.pack("<IHHHHH", method_rva, 0, 0, method, method_signature, 0)
    tables += struct.pack("<HHH", 0x0E, 4, constant_blob)
    tables += struct.pack("<HH", 2, 1)

    version = _pad4(b"v4.0.30319\x00")
    streams = [
        (stream_name, bytes(tables)),
        ("#Strings", bytes(strings)),
        ("#Blob", bytes(blobs)),
    ]
    if user_string is not None:
        raw = user_string.encode("utf-16-le")
        streams.append(("#US", bytes([0, len(raw)]) + raw))
    root = bytearray(b"BSJB")
    root += struct.pack("<HHII", 1, 1, 0, len(version))
    root += version
    root += struct.pack("<HH", 0, len(streams))
    headers = bytearray()
    data = bytearray()
    offset = len(root) + sum(8 + len(_pad4(name.encode() + b"\x00")) for name, _ in streams)
    for name, payload in streams:
        headers += struct.pack("<II", offset, len(payload)) + _pad4(name.encode() + b"\x00")
        data += payload
        offset += len(payload)
    return bytes(root) + bytes(headers) + bytes(data)


def _target(path: Path):  # type: ignore[no-untyped-def]
    parsed = parse_binary_target(str(path))
    assert parsed.ok
    return parsed.value


def _run(tmp_path: Path, **metadata: bytes | str) -> dict:  # type: ignore[no-untyped-def]
    path = tmp_path / "fixture.exe"
    path.write_bytes(build_pe(clr=True, metadata_blob=_metadata_blob(**metadata)))
    result = ManagedStaticProvider().analyze(
        "inspect_managed_members",
        _target(path),
        {"type_names": ["Example.Outer"], "include_bodies": False},
        None,
    )
    assert result.ok
    return result.value.result


def test_fields_constants_and_nesting(tmp_path: Path) -> None:
    result = _run(tmp_path)
    assert result["type_count"] == 2
    outer = result["types"][0]
    assert outer["full_name"] == "Example.Outer"
    assert outer["fields_total"] == 1
    field = result["fields"][0]
    assert field["name"] == "Value"
    assert field["constant"] == "literal"
    assert field["constant_type"] == "string"
    assert field["signature"]["field_type"] == "string"
    assert outer["methods"][0]["token"] == "0x06000001"
    assert outer["methods"][0]["signature"]["parameter_count"] == 0
    assert result["selection"] == {
        "type_names": ["Example.Outer"],
        "unmatched_type_names": [],
    }


def test_nested_type_name_and_enclosing_token(tmp_path: Path) -> None:
    path = tmp_path / "nested.exe"
    path.write_bytes(build_pe(clr=True, metadata_blob=_metadata_blob()))
    result = ManagedStaticProvider().analyze(
        "inspect_managed_members",
        _target(path),
        {"type_names": ["Inner"], "include_bodies": False},
        None,
    )
    assert result.ok
    data = result.value.result
    assert data["selection"]["unmatched_type_names"] == []
    assert data["types"][0]["full_name"] == "Example.Outer+Inner"
    assert data["types"][0]["enclosing_type_token"] == "0x02000001"
    assert data["nesting_read"] is True


def test_unselected_nested_type_has_no_outer_fields(tmp_path: Path) -> None:
    path = tmp_path / "unselected.exe"
    path.write_bytes(build_pe(clr=True, metadata_blob=_metadata_blob()))
    result = ManagedStaticProvider().analyze("inspect_managed_members", _target(path), {}, None)
    assert result.ok
    data = result.value.result
    outer = next(item for item in data["types"] if item["full_name"] == "Example.Outer")
    inner = next(item for item in data["types"] if item["full_name"] == "Example.Outer+Inner")
    assert outer["fields_total"] == 1
    assert outer["methods_total"] == 1
    assert inner["fields_total"] == 0
    assert inner["methods_total"] == 0
    assert data["fields"][0]["declaring_type"] == "Example.Outer"


def test_unoptimized_tables_stream_and_extra_data(tmp_path: Path) -> None:
    result = _run(
        tmp_path,
        stream_name="#-",
        extra_data=b"\x00\x00\x00\x00",
    )
    assert result["fields"][0]["constant"] == "literal"
    assert result["metadata"]["tables_stream"] == "#-"


def test_static_field_initializer_from_cctor(tmp_path: Path) -> None:
    path = tmp_path / "initializer.exe"
    body = bytes([0x2E, 0x72, 0x01, 0x00, 0x00, 0x70, 0x80, 0x01, 0x00, 0x00, 0x04, 0x2A])
    path.write_bytes(
        build_pe(
            clr=True,
            metadata_blob=_metadata_blob(
                method_rva=0x1400,
                user_string="overwrite",
            ),
            method_body=body,
        )
    )
    result = ManagedStaticProvider().analyze(
        "inspect_managed_members",
        _target(path),
        {"type_names": ["Example.Outer"], "include_bodies": True},
        None,
    )
    assert result.ok
    data = result.value.result
    assert data["field_initializers"] == [
        {
            "method_token": "0x06000001",
            "method": "Run",
            "field_token": "0x04000001",
            "field_name": "Value",
            "field_declaring_type": "Example.Outer",
            "value": "overwrite",
        }
    ]


def test_summary_keeps_counts_without_rows(tmp_path: Path) -> None:
    path = tmp_path / "summary.exe"
    path.write_bytes(build_pe(clr=True, metadata_blob=_metadata_blob()))
    result = ManagedStaticProvider().analyze(
        "inspect_managed_members",
        _target(path),
        {"detail": "summary"},
        None,
    )
    assert result.ok
    data = result.value.result
    summary = summarize_managed_inspection(data)
    assert data["types"] == []
    assert data["fields"] == []
    assert data["methods"] == []
    assert summary["reported_counts"]["types"] == 2
    assert summary["reported_counts"]["fields"] == 1
    assert summary["reported_counts"]["methods"] == 1


def test_managed_inspection_cache_hit(tmp_path: Path) -> None:
    from rea_mcp.providers.formats.managed_inspection import (
        clear_managed_cache,
        managed_cache_info,
    )

    clear_managed_cache()
    path = tmp_path / "cached.exe"
    path.write_bytes(build_pe(clr=True, metadata_blob=_metadata_blob()))
    for _ in range(2):
        result = ManagedStaticProvider().analyze("inspect_managed_members", _target(path), {}, None)
        assert result.ok
    info = managed_cache_info()
    assert info["hits"] == 1
    assert info["misses"] == 1
    clear_managed_cache()


def test_compare_managed_members_detects_field_constant_change(tmp_path: Path) -> None:
    from rea_mcp.providers.dotnet import compare_managed_members

    left = tmp_path / "left.exe"
    right = tmp_path / "right.exe"
    left.write_bytes(build_pe(clr=True, metadata_blob=_metadata_blob(constant="left")))
    right.write_bytes(build_pe(clr=True, metadata_blob=_metadata_blob(constant="right")))
    result = compare_managed_members(str(left), str(right))
    assert result.ok
    report = result.value
    assert report["status"] == "changed"
    assert report["fields"]["added_count"] == 1
    assert report["fields"]["removed_count"] == 1
    assert report["truncated"] is False
