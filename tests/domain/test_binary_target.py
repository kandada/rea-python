from pathlib import Path

from rea_mcp.domain.binary_target import detect_format, parse_binary_target


def test_detect_elf() -> None:
    fmt, _arch, _archs = detect_format(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"\x3e\x00")
    assert fmt == "elf"


def test_detect_wasm() -> None:
    assert detect_format(b"\x00asm\x01\x00\x00\x00")[0] == "wasm"


def test_detect_sqlite() -> None:
    assert detect_format(b"SQLite format 3\x00" + b"\x00" * 8)[0] == "sqlite"


def test_parse_elf_file(elf_file: Path) -> None:
    result = parse_binary_target(elf_file)
    assert result.ok
    assert result.value.format == "elf"
    assert result.value.architecture == "x86_64"
    assert result.value.kind == "executable"
    assert len(result.value.sha256) == 64


def test_parse_pe_file(pe_file: Path) -> None:
    result = parse_binary_target(pe_file)
    assert result.ok
    assert result.value.format == "pe"
    assert result.value.architecture == "x86_64"


def test_parse_macho_file(macho_file: Path) -> None:
    result = parse_binary_target(macho_file)
    assert result.ok
    assert result.value.format == "mach-o"
    assert result.value.architecture == "x86_64"


def test_missing_target_is_an_error(tmp_path: Path) -> None:
    result = parse_binary_target(tmp_path / "nope")
    assert not result.ok
    assert result.error.tag == "AnalysisInputError"


def test_directory_digest_is_stable(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("hello")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.txt").write_text("world")
    first = parse_binary_target(tmp_path)
    second = parse_binary_target(tmp_path)
    assert first.ok and second.ok
    assert first.value.sha256 == second.value.sha256
    assert first.value.kind == "directory"


def test_asar_extension_detection(tmp_path: Path) -> None:
    path = tmp_path / "app.asar"
    path.write_bytes(b"\x04\x00\x00\x00" + b"\x00" * 12)
    result = parse_binary_target(path)
    assert result.ok
    assert result.value.format == "asar"
