from __future__ import annotations

import struct

import pytest

from rea_mcp.providers.formats.axml import AxmlError, parse_axml

_NO_INDEX = 0xFFFFFFFF


def _string_pool(strings: list[str]) -> bytes:
    payload = bytearray()
    offsets: list[int] = []
    for value in strings:
        offsets.append(len(payload))
        encoded = value.encode("utf-16-le")
        payload += struct.pack("<H", len(value)) + encoded + b"\x00\x00"
    start = 28 + 4 * len(strings)
    total = start + len(payload)
    body = bytearray(total)
    struct.pack_into("<HHI", body, 0, 0x0001, 28, total)
    struct.pack_into("<IIIII", body, 8, len(strings), 0, 0, start, 0)
    for index, offset in enumerate(offsets):
        struct.pack_into("<I", body, 28 + index * 4, offset)
    body[start:] = payload
    return bytes(body)


def _element(name: str, attributes: dict[str, tuple[int, int]]) -> bytes:
    indexes = _STRING_INDEXES
    attr_start = 20
    body = bytearray(16)
    body += struct.pack("<II", _NO_INDEX, indexes[name])
    body += struct.pack("<HHHHHH", attr_start, 20, len(attributes), 0, 0, 0)
    for attr_name, (value, data_type) in attributes.items():
        raw = _NO_INDEX if data_type != 0x03 else value
        body += struct.pack("<IIIHBBI", _NO_INDEX, indexes[attr_name], raw, 8, 0, data_type, value)
    return struct.pack("<HHI", 0x0102, 16, len(body)) + bytes(body[8:])


_STRING_INDEXES: dict[str, int] = {}


def _document() -> bytes:
    strings = [
        "",
        "manifest",
        "package",
        "versionName",
        "versionCode",
        "application",
        "label",
        "debuggable",
        "uses-permission",
        "name",
        "activity",
        "exported",
        "permission",
        "com.example.demo",
        "1.2.3",
        "Demo",
        "android.permission.INTERNET",
        ".Main",
    ]
    _STRING_INDEXES.clear()
    _STRING_INDEXES.update({value: index for index, value in enumerate(strings)})
    chunks = [_string_pool(strings)]
    chunks.append(
        _element(
            "manifest",
            {
                "package": (13, 0x03),
                "versionName": (14, 0x03),
                "versionCode": (42, 0x10),
            },
        )
    )
    chunks.append(
        _element(
            "application",
            {
                "label": (15, 0x03),
                "debuggable": (1, 0x12),
            },
        )
    )
    chunks.append(
        _element(
            "uses-permission",
            {"name": (16, 0x03)},
        )
    )
    chunks.append(
        _element(
            "activity",
            {
                "name": (17, 0x03),
                "exported": (1, 0x12),
                "permission": (16, 0x03),
            },
        )
    )
    body = b"".join(chunks)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


def test_parse_axml_projects_manifest() -> None:
    result = parse_axml(_document())
    manifest = result["manifest"]
    assert manifest["package"] == "com.example.demo"
    assert manifest["version_name"] == "1.2.3"
    assert manifest["version_code"] == 42
    assert manifest["permissions"] == ["android.permission.INTERNET"]
    assert manifest["application"]["label"] == "Demo"
    assert manifest["application"]["debuggable"] is True
    assert manifest["components"]["activities"][0]["name"] == ".Main"
    assert manifest["components"]["activities"][0]["exported"] is True


def test_parse_axml_signed_and_reference_values() -> None:
    from rea_mcp.providers.formats.axml import _attribute_value

    assert _attribute_value(["x"], _NO_INDEX, 0x10, 0xFFFFFFFF) == -1
    assert _attribute_value(["x"], _NO_INDEX, 0x01, 0x7F010001) == "@0x7f010001"
    assert _attribute_value(["x"], _NO_INDEX, 0x99, 7) == 7
    assert _attribute_value(["zero", "one"], 1, 0x99, 10) == "one"


def test_parse_axml_rejects_bad_documents() -> None:
    with pytest.raises(AxmlError):
        parse_axml(b"short")
    with pytest.raises(AxmlError):
        parse_axml(struct.pack("<HHI", 0x0001, 8, 8))


def test_parse_axml_tolerates_truncated_chunks() -> None:
    document = _document()
    truncated = document[: 8 + 20]
    result = parse_axml(truncated)
    assert result["manifest"] is None
    assert result["elements"] == []


def test_parse_axml_utf8_pool_and_bad_offsets() -> None:
    from rea_mcp.providers.formats.axml import _parse_string_pool

    body = bytearray(28 + 8)
    struct.pack_into("<HHI", body, 0, 0x0001, 28, len(body))
    struct.pack_into("<IIIII", body, 8, 2, 0, 0x100, 36, 0)
    struct.pack_into("<II", body, 28, 0, 999)
    body.extend(b"\x03abc")
    strings = _parse_string_pool(bytes(body))
    assert strings[0] == "abc"
    assert strings[1] == ""
