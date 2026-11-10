from __future__ import annotations

import struct
import zipfile
from pathlib import Path

from rea_mcp.domain.binary_target import parse_binary_target
from rea_mcp.providers import java
from rea_mcp.providers.java import JavaProvider


def _target(path: Path):
    result = parse_binary_target(path)
    assert result.ok
    return result.value


def _utf8(value: str) -> bytes:
    raw = value.encode()
    return b"\x01" + struct.pack(">H", len(raw)) + raw


def _class() -> bytes:
    pool = [
        _utf8("com/example/Main"),
        b"\x07\x00\x01",
        _utf8("java/lang/Object"),
        b"\x07\x00\x03",
        _utf8("main"),
        _utf8("()V"),
        _utf8("Code"),
    ]
    constants = b"".join(pool)
    header = b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 52, len(pool) + 1)
    body = struct.pack(">HHH H", 0x0021, 2, 4, 0)
    body += struct.pack(">H", 0)
    body += struct.pack(">H", 1)
    body += struct.pack(">HHHH", 0x0001, 5, 6, 1)
    body += struct.pack(">HI", 7, 12)
    body += struct.pack(">HHIHH", 1, 1, 0, 0, 0)
    body += struct.pack(">H", 0)
    return header + constants + body


def test_parse_java_class_metadata(tmp_path: Path) -> None:
    path = tmp_path / "Main.class"
    path.write_bytes(_class())
    result = JavaProvider().analyze("inspect_java_class", _target(path), {}, None)
    assert result.ok, result
    payload = result.value.result
    assert payload["class"] == "com.example.Main"
    assert payload["super"] == "java.lang.Object"
    assert payload["flags"] == ["public", "super"]
    assert payload["methods"][0]["name"] == "main"
    assert payload["methods"][0]["code_length"] == 0


def test_java_archive_and_search(tmp_path: Path) -> None:
    archive = tmp_path / "app.jar"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("com/example/Main.class", _class())
        bundle.writestr(
            "META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nMain-Class: com.example.Main\n"
        )
        bundle.writestr("com/example/Helper.class", _class())
    provider = JavaProvider()
    result = provider.analyze("inspect_java_archive", _target(archive), {}, None)
    assert result.ok
    assert result.value.result["class_count"] == 2
    assert result.value.result["main_class"] == "com.example.Main"
    assert "com.example" in result.value.result["packages"]
    search = provider.analyze("search_java_classes", _target(archive), {"query": "helper"}, None)
    assert search.value.result["count"] == 1
    selected = provider.analyze(
        "inspect_java_class",
        _target(archive),
        {"class_name": "com.example.Main"},
        None,
    )
    assert selected.value.result["class"] == "com.example.Main"


def test_java_errors_and_capability(tmp_path: Path, monkeypatch) -> None:
    provider = JavaProvider()
    bad = tmp_path / "bad.class"
    bad.write_bytes(b"bad")
    assert not provider.analyze("inspect_java_class", _target(bad), {}, None).ok
    assert not provider.analyze("inspect_java_archive", _target(bad), {}, None).ok
    assert not provider.analyze("decompile_java_class", _target(bad), {}, None).ok
    assert not provider.analyze("unknown", _target(bad), {}, None).ok
    assert provider.supports(_target(bad)).status == "supported"
    assert JavaProvider().capabilities()[0].available is True

    empty = tmp_path / "empty.jar"
    with zipfile.ZipFile(empty, "w"):
        pass
    assert not provider.analyze("inspect_java_class", _target(empty), {}, None).ok
    monkeypatch.setattr(java, "_vineflower", lambda: None)
    result = provider.analyze("decompile_java_class", _target(bad), {}, None)
    assert not result.ok
    assert result.error.reason == "provider_unavailable"
