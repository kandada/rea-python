from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from rea_mcp.application.evidence_store import discover_store, nearest_project
from rea_mcp.application.project_store import create_project
from rea_mcp.cli.app import app

runner = CliRunner()


def _json(result) -> dict:  # type: ignore[no-untyped-def]
    assert result.exit_code == 0, result.output
    return json.loads(result.stdout)


def test_unknowns_persist_across_cli_invocations(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    recorded = _json(
        runner.invoke(
            app,
            [
                "record-unknown",
                str(target),
                "--question",
                "Does X exist?",
                "--domain",
                "TEST",
                "--severity",
                "low",
            ],
        )
    )
    unknown_id = recorded["unknown_id"]
    evidence_id = recorded["mutation_evidence_ids"][0]
    assert recorded["store"]["source"] == "sidecar"
    assert (target / ".rea/evidence.json").is_file()

    listed = _json(runner.invoke(app, ["list-unknowns", "--project", str(target)]))
    assert listed["count"] == 1
    assert listed["source"] == "sidecar"
    assert listed["unknowns"][0]["unknown_id"] == unknown_id

    updated = _json(
        runner.invoke(
            app,
            [
                "update-unknown",
                str(target),
                "--unknown-id",
                unknown_id,
                "--status",
                "investigating",
            ],
        )
    )
    assert updated["status"] == "investigating"
    investigating = _json(
        runner.invoke(
            app,
            ["list-unknowns", "--project", str(target), "--status", "investigating"],
        )
    )
    assert investigating["count"] == 1
    open_only = _json(
        runner.invoke(
            app,
            ["list-unknowns", "--project", str(target), "--status", "open"],
        )
    )
    assert open_only["count"] == 0

    fetched = _json(runner.invoke(app, ["evidence-get", evidence_id, "--project", str(target)]))
    assert fetched["evidence_id"] == evidence_id
    evidence = _json(
        runner.invoke(
            app,
            [
                "evidence-list",
                "--project",
                str(target),
                "--operation",
                "record_unknown",
                "--target",
                str(target),
            ],
        )
    )
    assert evidence["count"] >= 1
    wrong_target = _json(
        runner.invoke(
            app,
            [
                "evidence-list",
                "--project",
                str(target),
                "--target",
                str(tmp_path / "other"),
            ],
        )
    )
    assert wrong_target["count"] == 0
    bundle = _json(runner.invoke(app, ["get-evidence-bundle", "--project", str(target)]))
    assert bundle["kind"] == "bundle"
    assert bundle["record_count"] >= 1
    assert bundle["unknown_count"] >= 1


def test_unknown_store_resolves_project_root(tmp_path: Path) -> None:
    created = create_project(tmp_path / "project", name="Demo", request="x")
    assert created.ok
    nested = created.value.root / "app" / "asset.bin"
    nested.parent.mkdir(parents=True, exist_ok=True)
    nested.write_bytes(b"x")
    store = discover_store(target=nested)
    assert store.root == created.value.root
    assert store.project == created.value.root
    assert store.source == "project"
    recorded = _json(
        runner.invoke(
            app,
            [
                "record-unknown",
                str(nested),
                "--question",
                "q",
                "--domain",
                "d",
            ],
        )
    )
    assert recorded["store"]["source"] == "project"
    assert (created.value.root / ".rea/evidence.json").is_file()


def test_unknown_store_missing_source_is_explicit(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    payload = _json(runner.invoke(app, ["list-unknowns"]))
    assert payload["count"] == 0
    assert payload["source"] == "missing"
    assert payload["project"] is None
    assert Path(payload["store"]) == tmp_path / ".rea/evidence.json"


def test_nearest_project_and_invalid_store(tmp_path: Path) -> None:
    assert nearest_project(tmp_path) is None
    project = tmp_path / "project"
    project.mkdir()
    (project / "project.json").write_text("{}", encoding="utf-8")
    assert nearest_project(project / "deep" / "file") == project
    store = discover_store(project=project)
    store.path.parent.mkdir(parents=True)
    store.path.write_text("{bad", encoding="utf-8")
    loaded = store.load()
    assert not loaded.ok
    assert "unreadable" in loaded.error.message


def test_evidence_get_missing_id(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    result = runner.invoke(app, ["evidence-get", "ev_missing", "--project", str(target)])
    assert result.exit_code == 1
    assert "not found" in result.output


def test_evidence_store_env_project_and_bundle_export(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "target"
    target.mkdir()
    monkeypatch.setenv("REA_PROJECT", str(target))
    recorded = _json(
        runner.invoke(
            app,
            [
                "record-unknown",
                str(target),
                "--question",
                "q",
                "--domain",
                "D",
            ],
        )
    )
    assert recorded["store"]["path"] == str(target / ".rea/evidence.json")
    full = _json(runner.invoke(app, ["get-evidence-bundle", "--project", str(target), "--full"]))
    assert full["records"]
    export = tmp_path / "bundle.json"
    exported = _json(
        runner.invoke(
            app,
            ["export-evidence-bundle", "--project", str(target), "--path", str(export)],
        )
    )
    assert exported["record_count"] >= 1
    assert export.is_file()


def test_update_unknown_errors_for_missing_item(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    result = runner.invoke(
        app,
        [
            "update-unknown",
            str(target),
            "--unknown-id",
            "unk_missing",
            "--status",
            "investigating",
        ],
    )
    assert result.exit_code == 1
    assert "not-found" in result.output


def test_unknown_filters_limit_and_domain(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    for domain in ("A", "B"):
        _json(
            runner.invoke(
                app,
                [
                    "record-unknown",
                    str(target),
                    "--question",
                    domain,
                    "--domain",
                    domain,
                ],
            )
        )
    filtered = _json(
        runner.invoke(
            app,
            ["list-unknowns", "--project", str(target), "--domain", "A", "--limit", "1"],
        )
    )
    assert filtered["count"] == 1
    assert filtered["unknowns"][0]["domain"] == "A"
