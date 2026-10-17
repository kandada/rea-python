from pathlib import Path

from rea_mcp.application.session import BinarySession
from rea_mcp.composition.factories import create_binary_session
from rea_mcp.config.settings import AppConfig


def _session() -> BinarySession:
    return create_binary_session(AppConfig())


def test_open_binds_disjoint_providers(elf_file: Path) -> None:
    session = _session()
    result = session.open(str(elf_file))
    assert result.ok
    bound = {provider["id"] for provider in session.status()["bound_providers"]}
    assert {"binary-layout", "go", "rust", "artifacts"} <= bound


def test_execute_records_evidence_and_caches(elf_file: Path) -> None:
    session = _session()
    session.open(str(elf_file))
    first = session.execute("inspect_binary_layout")
    assert first.ok
    second = session.execute("inspect_binary_layout")
    assert second.ok
    assert first.value.evidence_id == second.value.evidence_id
    assert session.status()["evidence_count"] == 1


def test_unknown_operation_is_capability_error(elf_file: Path) -> None:
    session = _session()
    session.open(str(elf_file))
    result = session.execute("nonexistent_operation")
    assert not result.ok
    assert result.error.tag == "AnalysisCapabilityUnavailableError"


def test_execute_without_open_is_error() -> None:
    result = _session().execute("inspect_binary_layout")
    assert not result.ok
    assert result.error.tag == "NoBinaryOpenError"


def test_close_then_execute_errors(elf_file: Path) -> None:
    session = _session()
    session.open(str(elf_file))
    assert session.close().ok
    assert not session.execute("inspect_binary_layout").ok


def test_snapshot_round_trip(elf_file: Path, tmp_path: Path) -> None:
    session = _session()
    session.open(str(elf_file))
    session.execute("inspect_binary_layout")
    snapshot_path = tmp_path / "snap.json"
    written = session.write_snapshot(str(snapshot_path))
    assert written.ok
    assert snapshot_path.is_file()

    # A fresh session for the same target can import the snapshot.
    import json

    fresh = _session()
    fresh.open(str(elf_file))
    imported = fresh.import_snapshot(json.loads(snapshot_path.read_text()))
    assert imported.ok


def test_explicit_unknown_provider(elf_file: Path) -> None:
    session = _session()
    result = session.open(str(elf_file), provider_id="does-not-exist")
    assert not result.ok
    assert result.error.tag == "ProviderSelectionError"


def test_go_and_rust_route_to_their_providers(go_file: Path, rust_file: Path) -> None:
    go_session = _session()
    go_session.open(str(go_file))
    assert go_session.execute("inspect_go_binary").ok

    rust_session = _session()
    rust_session.open(str(rust_file))
    assert rust_session.execute("inspect_rust_binary").ok
