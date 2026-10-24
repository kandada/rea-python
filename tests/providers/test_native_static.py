from __future__ import annotations

from pathlib import Path

from rea_mcp.domain.binary_target import parse_binary_target
from rea_mcp.providers.javascript import JavaScriptApplicationProvider
from rea_mcp.providers.native_exports import NativeExportsProvider
from rea_mcp.providers.pe_certificates import PeCertificatesProvider


def _target(path: Path):  # type: ignore[no-untyped-def]
    parsed = parse_binary_target(str(path))
    assert parsed.ok
    return parsed.value


def test_pe_certificate_observed_absence(pe_file: Path) -> None:
    result = PeCertificatesProvider().analyze("inspect_pe_certificates", _target(pe_file), {}, None)
    assert result.ok
    assert result.value.result["has_certificate_table"] is False


def test_native_exports_observed_absence(pe_file: Path, elf_file: Path) -> None:
    for path in (pe_file, elf_file):
        result = NativeExportsProvider().analyze("inspect_native_exports", _target(path), {}, None)
        assert result.ok
        assert result.value.result["has_exports"] is False


def test_javascript_routes_static_candidates(tmp_path: Path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "server.js").write_text(
        "app.get('/api/users', handler);\n"
        "app.post('/api/items', fn);\n"
        "fetch('/health');\n"
        "const config = { path: '/api/config' };\n",
        encoding="utf-8",
    )
    result = JavaScriptApplicationProvider().analyze(
        "inspect_javascript_routes", _target(app), {"limit": 10}, None
    )
    assert result.ok
    data = result.value.result
    assert data["route_count"] == 4
    assert {route["path"] for route in data["routes"]} == {
        "/api/users",
        "/api/items",
        "/health",
        "/api/config",
    }
    assert data["by_kind"]["route"] == 2


def test_godot_pck_inventory(tmp_path: Path) -> None:
    import struct

    from rea_mcp.providers.artifact import ArtifactProvider

    path = tmp_path / "game.pck"
    header = bytearray(b"GDPC" + struct.pack("<IIII", 2, 4, 0, 0))
    header += struct.pack("<I", 0) + struct.pack("<Q", 0) + b"\x00" * 56
    payload = b"data"
    entry = (
        struct.pack("<I", 7)
        + b"res://a"
        + struct.pack("<QQ", 256, len(payload))
        + b"\x00" * 16
        + struct.pack("<I", 0)
    )
    data = bytes(header).ljust(96, b"\x00") + struct.pack("<I", 1) + entry
    data = data.ljust(256, b"\x00") + payload
    path.write_bytes(data)
    result = ArtifactProvider().analyze("inspect_artifact", _target(path), {}, None)
    assert result.ok
    assert result.value.result["format"] == "godot-pck"
    assert result.value.result["entries"][0]["path"] == "a"
    assert result.value.result["entries"][0]["size"] == 4
    assert result.value.result["entries"][0]["sha256"]
    assert result.value.result["declared_plaintext_bytes"] == 4


def test_native_function_matching(pe_file: Path) -> None:
    from rea_mcp.application.native_matching import match_native_functions

    result = match_native_functions(str(pe_file), str(pe_file))
    assert result["matched_count"] == 0
    assert result["added"] == []


def test_javascript_source_maps(tmp_path: Path) -> None:
    root = tmp_path / "web"
    root.mkdir()
    (root / "app.js").write_text(
        "console.log(1);\n//# sourceMappingURL=app.js.map\n", encoding="utf-8"
    )
    (root / "app.js.map").write_text(
        '{"version":3,"sources":["src/app.ts"],"names":[],"mappings":"AAAA"}',
        encoding="utf-8",
    )
    result = JavaScriptApplicationProvider().analyze(
        "inspect_javascript_source_maps", _target(root), {"line": 1, "column": 0}, None
    )
    assert result.ok
    data = result.value.result
    assert data["source_map_count"] == 1
    assert data["source_maps"][0]["source_count"] == 1
    assert data["source_maps"][0]["map_path"] == "app.js.map"
    assert data["source_maps"][0]["mapping_count"] == 1
    assert data["source_maps"][0]["lookup"]["original_line"] == 1


def test_javascript_webmcp_candidates(tmp_path: Path) -> None:
    root = tmp_path / "webmcp"
    root.mkdir()
    (root / "app.js").write_text(
        "navigator.modelContext.registerTool({name: 'search', inputSchema: {}});\n",
        encoding="utf-8",
    )
    result = JavaScriptApplicationProvider().analyze(
        "inspect_javascript_webmcp", _target(root), {}, None
    )
    assert result.ok
    data = result.value.result
    assert data["candidate_count"] >= 2
    assert any(item["name"] == "search" for item in data["candidates"])
