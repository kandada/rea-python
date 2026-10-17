from pathlib import Path

from rea_mcp.domain.binary_target import parse_binary_target
from rea_mcp.providers.android import AndroidProvider
from rea_mcp.providers.artifact import ArtifactProvider
from rea_mcp.providers.binary_layout import BinaryLayoutProvider
from rea_mcp.providers.dotnet import ManagedStaticProvider
from rea_mcp.providers.flutter import FlutterBuildProvider
from rea_mcp.providers.go import GoBinaryProvider
from rea_mcp.providers.rust import RustBinaryProvider
from rea_mcp.providers.sqlite import SqliteDatabaseProvider


def _target(path: Path) -> object:
    result = parse_binary_target(path)
    assert result.ok
    return result.value


def test_binary_layout_elf(elf_file: Path) -> None:
    provider = BinaryLayoutProvider()
    result = provider.analyze("inspect_binary_layout", _target(elf_file), {}, None)  # type: ignore[arg-type]
    assert result.ok
    assert result.value.result["format"] == "elf"
    assert result.value.result["type"] == "executable"


def test_binary_layout_pe(pe_file: Path) -> None:
    result = BinaryLayoutProvider().analyze("inspect_binary_layout", _target(pe_file), {}, None)  # type: ignore[arg-type]
    assert result.ok
    assert result.value.result["format"] == "pe"
    assert result.value.result["mitigations"]["nx"] is True
    assert result.value.result["mitigations"]["aslr"] is True


def test_macho_export_trie(macho_exports_file: Path) -> None:
    result = BinaryLayoutProvider().analyze(
        "inspect_binary_layout", _target(macho_exports_file), {}, None
    )  # type: ignore[arg-type]
    assert result.ok
    assert "main" in result.value.result["exports"]


def test_go_binary(go_file: Path) -> None:
    result = GoBinaryProvider().analyze("inspect_go_binary", _target(go_file), {}, None)  # type: ignore[arg-type]
    assert result.ok
    assert result.value.result["is_go"] is True
    assert result.value.result["compiler_version"] == "go1.22.3"
    assert {"path": "github.com/pkg/errors", "version": "v0.9.1"} in result.value.result["modules"]


def test_go_binary_on_plain_elf(elf_file: Path) -> None:
    result = GoBinaryProvider().analyze("inspect_go_binary", _target(elf_file), {}, None)  # type: ignore[arg-type]
    assert result.ok
    assert result.value.result["is_go"] is False


def test_rust_binary(rust_file: Path) -> None:
    result = RustBinaryProvider().analyze("inspect_rust_binary", _target(rust_file), {}, None)  # type: ignore[arg-type]
    assert result.ok
    assert result.value.result["has_dependency_metadata"] is True
    names = [package["name"] for package in result.value.result["packages"]]
    assert "serde" in names
    assert result.value.result["root_package"]["name"] == "app"


def test_rust_binary_without_section(elf_file: Path) -> None:
    result = RustBinaryProvider().analyze("inspect_rust_binary", _target(elf_file), {}, None)  # type: ignore[arg-type]
    assert result.ok
    assert result.value.result["has_dependency_metadata"] is False


def test_managed_not_managed(pe_file: Path) -> None:
    result = ManagedStaticProvider().analyze("inspect_managed_artifact", _target(pe_file), {}, None)  # type: ignore[arg-type]
    assert result.ok
    assert result.value.result["is_managed"] is False


def test_managed_assembly(pe_clr_file: Path) -> None:
    result = ManagedStaticProvider().analyze(
        "inspect_managed_artifact", _target(pe_clr_file), {}, None
    )  # type: ignore[arg-type]
    assert result.ok
    assert result.value.result["is_managed"] is True
    assert result.value.result["runtime_version"] == "v4.0.30319"


def test_managed_members(pe_clr_file: Path) -> None:
    result = ManagedStaticProvider().analyze(
        "inspect_managed_members", _target(pe_clr_file), {}, None
    )  # type: ignore[arg-type]
    assert result.ok
    assert result.value.result["type_count"] == 1
    types = result.value.result["types"]
    assert types[0]["full_name"] == "MyNamespace.MyType"
    methods = types[0]["methods"]
    assert [method["name"] for method in methods] == ["MyMethod"]
    assert methods[0]["rva"] == 0x1400


def test_disassemble_managed_method(pe_clr_file: Path) -> None:
    result = ManagedStaticProvider().analyze(
        "disassemble_managed_method",
        _target(pe_clr_file),
        {"method": "MyMethod"},
        None,  # type: ignore[arg-type]
    )
    assert result.ok
    instructions = result.value.result["instructions"]
    assert [instruction["opcode"] for instruction in instructions] == ["ldstr", "call", "ret"]
    assert instructions[0]["resolved"] == "hello"
    assert instructions[1]["resolved"] == "MyMethod"


def test_sqlite(sqlite_file: Path) -> None:
    result = SqliteDatabaseProvider().analyze(
        "inspect_sqlite_database", _target(sqlite_file), {}, None
    )  # type: ignore[arg-type]
    assert result.ok
    tables = {table["name"] for table in result.value.result["tables"]}
    assert "users" in tables
    users = next(table for table in result.value.result["tables"] if table["name"] == "users")
    assert [column["name"] for column in users["columns"]] == ["id", "name"]
    assert result.value.result["object_count"] >= 3


def test_sqlite_row_sample(sqlite_file: Path) -> None:
    result = SqliteDatabaseProvider().analyze(
        "inspect_sqlite_database",
        _target(sqlite_file),
        {"table": "users", "row_limit": 1},
        None,  # type: ignore[arg-type]
    )
    assert result.ok
    assert len(result.value.result["rows"]) == 1


def test_artifact_zip(zip_file: Path) -> None:
    result = ArtifactProvider().analyze("inspect_artifact", _target(zip_file), {}, None)  # type: ignore[arg-type]
    assert result.ok
    assert result.value.result["entry_count"] == 2
    assert result.value.result["entries"][0]["sha256"]


def test_android_apk(apk_file: Path) -> None:
    result = AndroidProvider().analyze("inspect_android_package", _target(apk_file), {}, None)  # type: ignore[arg-type]
    assert result.ok
    assert result.value.result["dex_files"] == ["classes.dex"]
    assert result.value.result["dex_versions"]["classes.dex"] == "035"


def test_flutter_apk(flutter_apk_file: Path) -> None:
    result = FlutterBuildProvider().analyze(
        "identify_flutter_build", _target(flutter_apk_file), {}, None
    )  # type: ignore[arg-type]
    assert result.ok
    assert result.value.result["is_flutter"] is True
    assert set(result.value.result["abis"]) == {"arm64-v8a", "x86_64"}
    assert result.value.result["consistent_snapshot"] is True
    assert result.value.result["snapshot_hashes"] == [bytes(range(16)).hex()]


def test_flutter_on_plain_apk(apk_file: Path) -> None:
    result = FlutterBuildProvider().analyze("identify_flutter_build", _target(apk_file), {}, None)  # type: ignore[arg-type]
    assert result.ok
    assert result.value.result["is_flutter"] is False
