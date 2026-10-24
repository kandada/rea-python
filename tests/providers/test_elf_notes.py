from __future__ import annotations

from pathlib import Path

from rea_mcp.domain.binary_target import parse_binary_target
from rea_mcp.providers.elf_notes import ElfNotesProvider


def _target(path: Path):  # type: ignore[no-untyped-def]
    parsed = parse_binary_target(str(path))
    assert parsed.ok
    return parsed.value


def test_elf_notes_observed_absence(elf_file: Path) -> None:
    result = ElfNotesProvider().analyze("inspect_elf_notes", _target(elf_file), {}, None)
    assert result.ok
    data = result.value.result
    assert data["has_notes"] is False
    assert data["table_count"] == 0
    assert data["note_count"] == 0
