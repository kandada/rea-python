import json
from pathlib import Path

import pytest

from rea_mcp.application import cli_compat
from rea_mcp.domain.analysis_error import AnalysisError
from rea_mcp.domain.reconstruction import Obligation, build_ledger


def _wasm_with_export(name: str) -> bytes:
    encoded = name.encode()
    body = bytes([1, len(encoded)]) + encoded + bytes([0, 0])
    return b"\x00asm\x01\x00\x00\x00" + bytes([7, len(body)]) + body


def test_list_architectures() -> None:
    result = cli_compat.list_architectures()
    assert "x86_64" in result["elf"]
    assert "arm64" in result["mach-o"]


def test_read_and_search_bytes(tmp_path: Path) -> None:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"\x00\x01hello\x02world")
    read = cli_compat.read_bytes(str(path), 2, 5)
    assert read["hex"] == b"hello".hex()
    assert read["ascii"] == "hello"
    found = cli_compat.search_bytes(str(path), "hello")
    assert [hit["file_offset"] for hit in found["hits"]] == [2]
    hex_found = cli_compat.search_bytes(str(path), "776f726c64", hex_pattern=True)
    assert [hit["file_offset"] for hit in hex_found["hits"]] == [8]


def test_address_to_file_offset_elf(elf_file: Path) -> None:
    result = cli_compat.address_to_file_offset(str(elf_file), "0x0")
    assert result["mapped"] is True
    assert result["file_offset"] is not None


def test_inspect_macho(macho_file: Path) -> None:
    result = cli_compat.inspect_macho(str(macho_file))
    assert result["filetype"] == "executable"
    assert result["architecture"]


def test_extract_artifact(zip_file: Path, tmp_path: Path) -> None:
    result = cli_compat.extract_artifact(str(zip_file), str(tmp_path / "out"))
    assert result["extracted_count"] == 2
    assert (tmp_path / "out" / "a.txt").is_file()


def test_compare_wasm_interfaces(tmp_path: Path) -> None:
    left = tmp_path / "a.wasm"
    right = tmp_path / "b.wasm"
    left.write_bytes(_wasm_with_export("alpha"))
    right.write_bytes(_wasm_with_export("beta"))
    result = cli_compat.compare_wasm_interfaces(str(left), str(right))
    assert result["added_exports"] == ["beta"]
    assert result["removed_exports"] == ["alpha"]


def test_compare_javascript_export_shapes(tmp_path: Path) -> None:
    left = tmp_path / "a.js"
    right = tmp_path / "b.js"
    left.write_text("export const alpha = 1;\nexport function beta() {}\n")
    right.write_text("export const alpha = 1;\nexport class gamma {}\n")
    result = cli_compat.compare_javascript_export_shapes(str(left), str(right))
    assert result["added"] == ["gamma"]
    assert result["removed"] == ["beta"]


def test_project_harmony_graph(hap_file: Path) -> None:
    result = cli_compat.project_harmony_application_graph(str(hap_file))
    assert result["nodes"]
    assert any(node["kind"] == "abc" for node in result["nodes"])


def test_project_apple_graph(tmp_path: Path) -> None:
    import plistlib
    import shutil

    if not Path("/bin/echo").is_file():
        pytest.skip("no Mach-O executable available")
    root = tmp_path / "Demo.app"
    root.mkdir()
    (root / "Info.plist").write_bytes(
        plistlib.dumps(
            {
                "CFBundleIdentifier": "com.example.demo",
                "CFBundleExecutable": "Demo",
                "CFBundleShortVersionString": "1.2.3",
            }
        )
    )
    shutil.copyfile("/bin/echo", root / "Demo")
    (root / "libdemo.dylib").write_bytes(b"\x00")
    result = cli_compat.project_apple_application_graph(str(root))
    assert result["bundle_id"] == "com.example.demo"
    assert result["executable"] == "Demo"
    assert any(node["kind"] == "executable" for node in result["nodes"])
    assert any(node["kind"] == "dylib" for node in result["nodes"])


def test_project_managed_graph(pe_clr_file: Path) -> None:
    result = cli_compat.project_managed_application_graph(str(pe_clr_file))
    assert any(node["kind"] == "type" for node in result["nodes"])
    assert any(node["kind"] == "method" for node in result["nodes"])


def test_import_managed_reconstruction(tmp_path: Path) -> None:
    ledger = build_ledger(
        [Obligation(name="main", required_facets=["pseudo"], provided_facets=["pseudo"])]
    )
    path = tmp_path / "ledger.json"
    path.write_text(json.dumps(ledger.model_dump()), encoding="utf-8")
    result = cli_compat.import_managed_reconstruction(str(path))
    assert result["coverage"]["complete"] is True


def test_managed_native_boundaries(pe_clr_file: Path) -> None:
    result = cli_compat.inspect_managed_native_boundaries(str(pe_clr_file))
    assert "markers" in result
    verified = cli_compat.verify_managed_native_boundaries(str(pe_clr_file), ["MyMethod"])
    assert verified["boundaries"][0]["present"] is True


def test_uninstall_config(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"mcpServers": {"rea-mcp": {"command": "rea-mcp"}}}))
    skill = tmp_path / "skills"
    (skill / "reverse-engineer-anything").mkdir(parents=True)
    removed = cli_compat.uninstall(str(config), str(skill))
    assert removed == {"removed_config_entry": True, "removed_skill": True}
    assert "rea-mcp" not in json.loads(config.read_text())["mcpServers"]
    assert not (skill / "reverse-engineer-anything").exists()


def _pad4(data: bytes) -> bytes:
    return data + b"\x00" * ((4 - len(data) % 4) % 4)


def _metadata_with_pinvoke() -> bytes:
    import struct

    strings = b"\x00MyMethod\x00libSystem\x00puts\x00"
    valid = (1 << 0x00) | (1 << 0x06) | (1 << 0x1A) | (1 << 0x1C)
    tables = bytearray()
    tables += struct.pack("<I", 0)
    tables += struct.pack("<BBBB", 2, 0, 0, 0)
    tables += struct.pack("<Q", valid)
    tables += struct.pack("<Q", 0)
    for count in (1, 1, 1, 1):  # Module, MethodDef, ModuleRef, ImplMap
        tables += struct.pack("<I", count)
    # Module: Generation, Name, Mvid, EncId, EncBaseId
    tables += struct.pack("<HHHHH", 0, 0, 0, 0, 0)
    # MethodDef: RVA, ImplFlags, Flags, Name, Signature, ParamList
    tables += struct.pack("<IHHHHH", 0x1400, 0, 0, 1, 0, 0)
    # ModuleRef: Name=libSystem
    tables += struct.pack("<H", 10)
    # ImplMap: Flags, MemberForwarded (MethodDef row 1), ImportName=puts, ImportScope=ModuleRef row 1
    tables += struct.pack("<HHHH", 0, 3, 20, 1)
    streams = [("#~", bytes(tables)), ("#Strings", strings)]
    version = _pad4(b"v4.0.30319\x00")
    root = b"BSJB" + struct.pack("<HHII", 1, 1, 0, len(version)) + version
    root += struct.pack("<HH", 0, len(streams))
    headers = bytearray()
    data = bytearray()
    offset = len(root) + sum(8 + len(_pad4(name.encode() + b"\x00")) for name, _ in streams)
    for name, payload in streams:
        headers += struct.pack("<II", offset, len(payload)) + _pad4(name.encode() + b"\x00")
        data += payload
        offset += len(payload)
    return root + bytes(headers) + bytes(data)


def test_parse_pinvoke_implmap() -> None:
    import tests.conftest as conftest

    blob = _metadata_with_pinvoke()
    assembly = conftest.build_pe(clr=True, metadata_blob=blob)
    result = cli_compat.inspect_managed_native_boundaries_for_bytes(assembly)
    assert result["pinvoke_count"] == 1
    entry = result["pinvoke"][0]
    assert entry["method"] == "MyMethod"
    assert entry["native_library"] == "libSystem"
    assert entry["entry_point"] == "puts"


def test_native_boundaries_verification() -> None:
    import tests.conftest as conftest

    assembly = conftest.build_pe(clr=True, metadata_blob=_metadata_with_pinvoke())
    result = cli_compat.verify_managed_native_boundaries_for_bytes(assembly, ["MyMethod", "puts"])
    assert result["verified"] is True
    assert result["boundaries"][0]["source"] == "implmap"


def test_demangle_swift_real() -> None:
    import shutil

    if not shutil.which("xcrun"):
        pytest.skip("xcrun is unavailable")
    result = cli_compat.demangle_swift(["_$s4main3fooyyF"])
    if result.get("demangled") is None:
        pytest.skip(result.get("limitation") or "swift-demangle unavailable")
    joined = "\n".join(result["demangled"])
    assert "main.foo" in joined


def test_trace_dylib_resolution_requires_allow(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError):
        cli_compat.trace_dylib_resolution("/bin/echo", allow_execute=False)


def test_trace_dylib_resolution_real() -> None:
    import os

    if not os.path.exists("/bin/echo"):
        pytest.skip("no /bin/echo")
    result = cli_compat.trace_dylib_resolution(
        "/bin/echo", allow_execute=True, args=["hello"], timeout=30
    )
    assert result["exit_code"] == 0
    assert isinstance(result["libraries"], list)


def test_native_runtime_gates() -> None:
    with pytest.raises(AnalysisError):
        cli_compat.observe_native_calls("/bin/sleep", spawn=True, allow_execute=False)
    with pytest.raises(AnalysisError):
        cli_compat.observe_native_calls("999999", duration=0.1, timeout=2)
    with pytest.raises(AnalysisError):
        cli_compat.observe_native_ui("Finder", allow_ui=False)


def test_inspect_native_dispatch_metadata_real(tmp_path: Path) -> None:
    import shutil
    import subprocess

    if not shutil.which("xcrun"):
        pytest.skip("xcrun is unavailable")
    source = tmp_path / "demo.m"
    source.write_text(
        "#import <Foundation/Foundation.h>\n"
        "@interface Foo : NSObject\n- (void)bar;\n@end\n"
        "@implementation Foo\n- (void)bar {}\n@end\n"
        "int main(void) { return 0; }\n",
        encoding="utf-8",
    )
    binary = tmp_path / "demo"
    compiled = subprocess.run(
        ["xcrun", "clang", "-framework", "Foundation", "-o", str(binary), str(source)],
        capture_output=True,
        text=True,
        check=False,
    )
    if compiled.returncode != 0:
        pytest.skip(f"clang unavailable: {compiled.stderr[-200:]}")
    result = cli_compat.inspect_native_dispatch_metadata(str(binary))
    assert result["has_objc"] is True
    assert "Foo" in result["classes"]
    assert "bar" in result["selectors"]


def test_address_aware_read_and_search(elf_file: Path) -> None:
    read = cli_compat.read_bytes(str(elf_file), length=4, address="0x0")
    assert read["offset"] == 64
    assert read["address"] == 0
    found = cli_compat.search_bytes(str(elf_file), "90", hex_pattern=True, address="0x0")
    assert found["match_count"] >= 1
    assert found["hits"][0]["virtual_address"] == 0


def test_inspect_signature_real(tmp_path: Path) -> None:
    import shutil
    import subprocess

    import pytest as _pytest

    if not shutil.which("codesign"):
        _pytest.skip("codesign is unavailable")
    source = tmp_path / "demo.c"
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    binary = tmp_path / "demo"
    compiled = subprocess.run(
        ["xcrun", "clang", "-o", str(binary), str(source)],
        capture_output=True,
        text=True,
        check=False,
    )
    if compiled.returncode != 0:
        _pytest.skip(f"clang unavailable: {compiled.stderr[-200:]}")
    entitlements = tmp_path / "ent.plist"
    entitlements.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<plist version="1.0"><dict>'
        "<key>com.apple.security.get-task-allow</key><true/>"
        "</dict></plist>",
        encoding="utf-8",
    )
    signed = subprocess.run(
        [
            "codesign",
            "--force",
            "--sign",
            "-",
            "--entitlements",
            str(entitlements),
            str(binary),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if signed.returncode != 0:
        _pytest.skip(f"codesign failed: {signed.stderr[-200:]}")
    result = cli_compat.inspect_signature(str(binary))
    assert result["has_code_signature"] is True
    directory = result["code_directory"]
    assert directory["hash_type"] == "sha256"
    assert len(directory["cdhash"]) == 40
    assert result["entitlements"]["com.apple.security.get-task-allow"] is True


def test_project_harmony_graph_with_abilities(tmp_path: Path) -> None:
    import json as _json
    import zipfile

    path = tmp_path / "entry.hap"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "module.json",
            _json.dumps(
                {
                    "app": {"bundleName": "com.example.hap", "versionName": "1.0"},
                    "module": {
                        "name": "entry",
                        "abilities": [{"name": "EntryAbility", "exported": True}],
                    },
                }
            ),
        )
        archive.writestr("ets/entry.abc", b"abc")
    result = cli_compat.project_harmony_application_graph(str(path))
    assert any(node["kind"] == "ability" for node in result["nodes"])
    assert any(edge["kind"] == "contains" for edge in result["edges"])


def _universal_binary() -> Path:
    candidate = Path("/bin/echo")
    if not candidate.is_file():
        pytest.skip("no system Mach-O binary")
    with candidate.open("rb") as handle:
        magic = handle.read(4)
    if magic not in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        pytest.skip("system binary is not a universal Mach-O")
    return candidate


def test_inspect_macho_universal() -> None:
    binary = _universal_binary()
    result = cli_compat.inspect_macho(str(binary))
    assert result["format"] == "mach-o-universal"
    assert result["slice_count"] >= 2
    assert {item["architecture"] for item in result["slices"]} >= {"x86_64", "arm64"}


def test_inspect_signature_universal() -> None:
    binary = _universal_binary()
    result = cli_compat.inspect_signature(str(binary))
    assert result["format"] == "mach-o-universal"
    assert result["slices"]
    directories = [
        item["code_directory"] for item in result["slices"] if item.get("code_directory")
    ]
    assert directories
    assert directories[0]["cdhash"]


def test_universal_address_mapping() -> None:
    binary = _universal_binary()
    summary = cli_compat.inspect_macho(str(binary))
    arm = next(item for item in summary["slices"] if item["architecture"] == "arm64")
    text = next(segment for segment in arm["segments"] if segment["name"] == "__TEXT")
    mapped = cli_compat.address_to_file_offset(str(binary), hex(text["vmaddr"]))
    assert mapped["mapped"] is True
    assert mapped["file_offset"] is not None
    read = cli_compat.read_bytes(str(binary), length=4, address=hex(text["vmaddr"]))
    assert read["address"] == text["vmaddr"]


def test_extract_dmg(tmp_path: Path) -> None:
    import shutil
    import subprocess

    import pytest as _pytest

    if not shutil.which("hdiutil"):
        _pytest.skip("hdiutil is unavailable")
    source = tmp_path / "source"
    source.mkdir()
    (source / "hello.txt").write_text("hello dmg", encoding="utf-8")
    dmg = tmp_path / "sample.dmg"
    created = subprocess.run(
        [
            "hdiutil",
            "create",
            "-volname",
            "rea-test",
            "-srcfolder",
            str(source),
            "-ov",
            "-format",
            "UDZO",
            str(dmg),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if created.returncode != 0:
        _pytest.skip(f"hdiutil create failed: {created.stderr[-200:]}")
    output = tmp_path / "out"
    result = cli_compat.extract_artifact(str(dmg), str(output))
    assert result["format"] == "dmg"
    assert (output / "hello.txt").read_text(encoding="utf-8") == "hello dmg"
