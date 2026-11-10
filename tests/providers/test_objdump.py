from __future__ import annotations

from pathlib import Path

from rea_mcp.domain.binary_target import parse_binary_target
from rea_mcp.providers.objdump import ObjdumpProvider, _parse_sections


def _target(path: Path):
    result = parse_binary_target(path)
    assert result.ok
    return result.value


def _script(tmp_path: Path) -> Path:
    script = tmp_path / "objdump"
    script.write_text(
        "#!/bin/sh\n"
        'case "$1" in\n'
        "  -f) echo 'file format elf64-x86-64' ;;\n"
        "  -h) printf 'Sections:\\nIdx Name          Size\\n  0 .text         000001\\n  1 .data         000002\\n  2 .bss          000000\\n' ;;\n"
        "  *) echo unsupported; exit 2 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def test_objdump_inspects_headers(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "a.out"
    target.write_bytes(b"\x7fELF")
    monkeypatch.setenv("REA_OBJDUMP", str(_script(tmp_path)))
    result = ObjdumpProvider().analyze("inspect_with_objdump", _target(target), {}, None)
    assert result.ok, result
    assert "elf64" in result.value.result["file"]
    assert result.value.result["sections"] == [
        {"index": 0, "name": ".text"},
        {"index": 1, "name": ".data"},
        {"index": 2, "name": ".bss"},
    ]


def test_objdump_unavailable_is_actionable(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "a.out"
    target.write_bytes(b"\x7fELF")
    monkeypatch.setenv("REA_OBJDUMP", str(tmp_path / "missing"))
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    result = ObjdumpProvider().analyze("inspect_with_objdump", _target(target), {}, None)
    assert not result.ok
    assert result.error.reason == "provider_unavailable"
    assert result.error.remediation_action


def test_objdump_rejects_unknown_operation(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "a.out"
    target.write_bytes(b"\x7fELF")
    monkeypatch.setenv("REA_OBJDUMP", str(_script(tmp_path)))
    result = ObjdumpProvider().analyze("inspect_with_objdump", _target(target), {}, None)
    assert result.ok
    result = ObjdumpProvider().analyze("other", _target(target), {}, None)
    assert not result.ok
    assert "unsupported operation" in result.error.message


def test_objdump_supports_and_capabilities(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "a.out"
    target.write_bytes(b"\x7fELF")
    monkeypatch.setenv("REA_OBJDUMP", str(_script(tmp_path)))
    assert ObjdumpProvider().supports(_target(target)).status == "supported"
    capabilities = ObjdumpProvider().capabilities()
    assert capabilities[0].available is True
    assert capabilities[0].effects.launches_process is True


def test_parse_sections_ignores_noise() -> None:
    text = "\nSections:\nIdx Name\n0 .text 1\nx .bad\n 12 .rodata 2\n"
    assert _parse_sections(text) == [
        {"index": 0, "name": ".text"},
        {"index": 12, "name": ".rodata"},
    ]
