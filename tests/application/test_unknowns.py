from pathlib import Path

from rea_mcp.composition.factories import create_binary_session
from rea_mcp.config.settings import AppConfig


def _session(elf_file: Path):
    session = create_binary_session(AppConfig())
    session.open(str(elf_file))
    return session


def test_record_update_list(elf_file: Path) -> None:
    session = _session(elf_file)
    recorded = session.record_unknown("Is the parser reachable?", "reachability", severity="high")
    assert recorded.ok
    assert recorded.value["status"] == "open"
    unknown_id = recorded.value["unknown_id"]

    listed = session.list_unknowns()
    assert any(unknown["unknown_id"] == unknown_id for unknown in listed)

    updated = session.update_unknown(unknown_id, "investigating")
    assert updated.ok
    assert updated.value["revision"] == 2


def test_resolved_requires_resolution(elf_file: Path) -> None:
    session = _session(elf_file)
    unknown_id = session.record_unknown("q", "domain").value["unknown_id"]  # type: ignore[union-attr]

    bad = session.update_unknown(unknown_id, "resolved")
    assert not bad.ok

    good = session.update_unknown(
        unknown_id,
        "resolved",
        resolution={
            "disposition": "verified",
            "rationale": "confirmed",
            "evidence_ids": ["ev_" + "0" * 64],
        },
    )
    assert good.ok
    assert good.value["status"] == "resolved"


def test_update_missing_unknown(elf_file: Path) -> None:
    session = _session(elf_file)
    assert not session.update_unknown("unk_" + "0" * 64, "investigating").ok
