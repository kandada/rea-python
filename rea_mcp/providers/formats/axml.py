"""Minimal Android binary XML (AXML) reader.

Enough to recover manifest-level facts (package, versionName, versionCode) from
``AndroidManifest.xml`` inside an APK, without executing the app.
"""

from __future__ import annotations

import struct
from typing import Any

RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_RESOURCE_MAP_TYPE = 0x0180

_UTF8_FLAG = 0x100
_NO_INDEX = 0xFFFFFFFF

_TYPE_STRING = 0x03
_TYPE_INT_DEC = 0x10
_TYPE_INT_HEX = 0x11
_TYPE_BOOLEAN = 0x12
_TYPE_REFERENCE = 0x01


class AxmlError(ValueError):
    pass


def parse_axml(data: bytes) -> dict[str, Any]:
    """Return a small projection of an AXML document."""

    if len(data) < 8:
        raise AxmlError("AXML document is truncated")
    chunk_type, _header_size, _chunk_size = struct.unpack_from("<HHI", data, 0)
    if chunk_type != RES_XML_TYPE:
        raise AxmlError("Not an AXML document")

    strings: list[str] = []
    elements: list[dict[str, Any]] = []
    offset = 8
    while offset + 8 <= len(data):
        ctype, header_size, csize = struct.unpack_from("<HHI", data, offset)
        if csize < 8 or offset + csize > len(data):
            break
        body = data[offset : offset + csize]
        if ctype == RES_STRING_POOL_TYPE:
            strings = _parse_string_pool(body)
        elif ctype == RES_XML_START_ELEMENT_TYPE:
            element = _parse_start_element(body, header_size, strings)
            if element is not None:
                elements.append(element)
        offset += csize

    return {"strings": strings, "elements": elements, "manifest": _project_manifest(elements)}


def _parse_string_pool(body: bytes) -> list[str]:
    if len(body) < 28:
        return []
    string_count, _style_count, flags, strings_start, _styles_start = struct.unpack_from(
        "<IIIII", body, 8
    )
    offsets = struct.unpack_from(f"<{string_count}I", body, 28)
    is_utf8 = bool(flags & _UTF8_FLAG)
    result: list[str] = []
    for string_offset in offsets:
        start = strings_start + string_offset
        if start >= len(body):
            result.append("")
            continue
        try:
            if is_utf8:
                result.append(_read_utf8(body, start))
            else:
                result.append(_read_utf16(body, start))
        except (struct.error, IndexError):
            result.append("")
    return result


def _read_utf8(body: bytes, start: int) -> str:
    length, cursor = _read_length8(body, start)
    raw = body[cursor : cursor + length]
    return raw.decode("utf-8", errors="replace")


def _read_utf16(body: bytes, start: int) -> str:
    length = struct.unpack_from("<H", body, start)[0]
    cursor = start + 2
    if length & 0x8000:
        length = ((length & 0x7FFF) << 16) | struct.unpack_from("<H", body, cursor)[0]
        cursor += 2
    raw = body[cursor : cursor + length * 2]
    return raw.decode("utf-16-le", errors="replace")


def _read_length8(body: bytes, start: int) -> tuple[int, int]:
    first = body[start]
    if first & 0x80:
        length = ((first & 0x7F) << 8) | body[start + 1]
        return length, start + 2
    return first, start + 1


def _parse_start_element(
    body: bytes, header_size: int, strings: list[str]
) -> dict[str, Any] | None:
    cursor = header_size
    try:
        _namespace, name_index = struct.unpack_from("<II", body, cursor)
        cursor += 8
        attr_start, _attr_size, attr_count, _id_index, _class_index, _style_index = (
            struct.unpack_from("<HHHHHH", body, cursor)
        )
        cursor = header_size + attr_start
    except struct.error:
        return None
    name = _string(strings, name_index)
    attributes: dict[str, Any] = {}
    for _ in range(attr_count):
        if cursor + 20 > len(body):
            break
        ns_index, attr_name_index, raw_value = struct.unpack_from("<III", body, cursor)
        data_type = body[cursor + 15]
        data_value = struct.unpack_from("<I", body, cursor + 16)[0]
        cursor += 20
        attr_name = _string(strings, attr_name_index)
        if not attr_name:
            continue
        del ns_index
        attributes[attr_name] = _attribute_value(strings, raw_value, data_type, data_value)
    return {"name": name, "attributes": attributes}


def _attribute_value(strings: list[str], raw_value: int, data_type: int, data_value: int) -> Any:
    if raw_value != _NO_INDEX:
        return _string(strings, raw_value)
    if data_type == _TYPE_STRING:
        return _string(strings, data_value)
    if data_type == _TYPE_INT_DEC:
        return _signed32(data_value)
    if data_type == _TYPE_INT_HEX:
        return _signed32(data_value)
    if data_type == _TYPE_BOOLEAN:
        return bool(data_value)
    if data_type == _TYPE_REFERENCE:
        return f"@{data_value:#010x}"
    return data_value


def _signed32(value: int) -> int:
    return int(struct.unpack("<i", struct.pack("<I", value))[0])


def _string(strings: list[str], index: int) -> str:
    if index == _NO_INDEX or index >= len(strings):
        return ""
    return strings[index]


_COMPONENT_ELEMENTS = {
    "activity": "activities",
    "activity-alias": "activity_aliases",
    "service": "services",
    "receiver": "receivers",
    "provider": "providers",
}
_COMPONENT_ATTRIBUTES = (
    "name",
    "exported",
    "permission",
    "enabled",
    "launchMode",
    "process",
    "authorities",
)


def _project_manifest(elements: list[dict[str, Any]]) -> dict[str, Any] | None:
    manifest: dict[str, Any] | None = None
    permissions: list[str] = []
    components: dict[str, list[dict[str, Any]]] = {
        "activities": [],
        "activity_aliases": [],
        "services": [],
        "receivers": [],
        "providers": [],
    }
    application: dict[str, Any] = {}
    for element in elements:
        name = element["name"]
        attributes = element["attributes"]
        if name == "manifest":
            manifest = {
                "package": attributes.get("package"),
                "version_name": attributes.get("versionName"),
                "version_code": attributes.get("versionCode"),
            }
        elif name == "uses-permission":
            permission = attributes.get("name")
            if permission:
                permissions.append(str(permission))
        elif name == "application":
            application = {
                key: attributes.get(key)
                for key in (
                    "name",
                    "label",
                    "debuggable",
                    "allowBackup",
                    "usesCleartextTraffic",
                    "networkSecurityConfig",
                )
                if attributes.get(key) is not None
            }
        elif name in _COMPONENT_ELEMENTS:
            entry = {
                key: attributes.get(key)
                for key in _COMPONENT_ATTRIBUTES
                if attributes.get(key) is not None
            }
            if entry.get("name"):
                components[_COMPONENT_ELEMENTS[name]].append(entry)
    if manifest is None:
        return None
    manifest["permissions"] = sorted(set(permissions))
    manifest["components"] = components
    manifest["application"] = application
    return manifest


__all__ = ["AxmlError", "parse_axml"]
