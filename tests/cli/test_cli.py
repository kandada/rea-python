import json
from pathlib import Path

from typer.testing import CliRunner

from rea_mcp.cli.app import app

runner = CliRunner()


def test_inspect_binary_layout(elf_file: Path) -> None:
    result = runner.invoke(app, ["inspect-binary-layout", str(elf_file)])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["evidence_id"].startswith("ev_")
    assert payload["normalized_result"]["format"] == "elf"


def test_providers_command() -> None:
    result = runner.invoke(app, ["providers"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert any(provider["id"] == "binary-layout" for provider in payload["providers"])


def test_capabilities_command() -> None:
    result = runner.invoke(app, ["capabilities"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert "inspect_go_binary" in payload["operations"]


def test_missing_target_fails(tmp_path: Path) -> None:
    result = runner.invoke(app, ["inspect-binary-layout", str(tmp_path / "nope")])
    assert result.exit_code == 1


def test_sqlite_command(sqlite_file: Path) -> None:
    result = runner.invoke(app, ["inspect-sqlite-database", str(sqlite_file), "--table", "users"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["normalized_result"]["rows"]


def test_analysis_view_command(tmp_path: Path, elf_file: Path) -> None:
    inspect = runner.invoke(app, ["inspect-binary-layout", str(elf_file)])
    record_path = tmp_path / "record.json"
    record_path.write_text(inspect.stdout, encoding="utf-8")
    view = runner.invoke(app, ["inspect-analysis-view", str(record_path)])
    assert view.exit_code == 0
    payload = json.loads(view.stdout)
    assert payload["kind"] == "record"


def test_doctor_command() -> None:
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert "healthy" in payload
    assert any(entry["id"] == "binary-layout" for entry in payload["providers"])


def test_capture_process_command() -> None:
    import sys

    result = runner.invoke(app, ["capture-process", "--", sys.executable, "-c", "print('hi')"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["stdout"].strip() == "hi"


def test_compare_command(tmp_path: Path, elf_file: Path) -> None:
    first = runner.invoke(app, ["inspect-binary-layout", str(elf_file)])
    left = tmp_path / "left.json"
    right = tmp_path / "right.json"
    left.write_text(first.stdout, encoding="utf-8")
    right.write_text(first.stdout, encoding="utf-8")
    result = runner.invoke(app, ["compare", str(left), str(right)])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "unchanged"


def test_import_reference_source_command(source_dir: Path) -> None:
    result = runner.invoke(app, ["import-reference-source", str(source_dir)])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["normalized_result"]["file_count"] >= 2


def test_inspect_plist_command(plist_file: Path) -> None:
    result = runner.invoke(app, ["inspect-plist", str(plist_file)])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["normalized_result"]["plist_format"] == "xml"


def test_managed_members_summary_bundle_and_view(pe_clr_file: Path, tmp_path: Path) -> None:
    bundle = tmp_path / "managed-bundle.json"
    result = runner.invoke(
        app,
        [
            "inspect-managed-members",
            str(pe_clr_file),
            "--type",
            "MyNamespace.MyType",
            "--detail",
            "summary",
            "--evidence-bundle",
            str(bundle),
        ],
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["summary"]["reported_counts"]["methods"] == 1
    assert payload["summary"]["selection"]["unmatched_type_names"] == []
    assert bundle.is_file()

    view = runner.invoke(
        app,
        [
            "inspect-analysis-view",
            str(bundle),
            "--view",
            "managed-members",
            "--collection",
            "methods",
        ],
    )
    assert view.exit_code == 0, view.stdout
    projected = json.loads(view.stdout)
    assert projected["total"] == 1
    assert projected["rows"][0]["name"] == "MyMethod"


def test_cli_output_budget_writes_full_payload(pe_clr_file: Path, tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--output-budget", "100", "inspect-managed-members", str(pe_clr_file)],
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["truncated"] is True
    assert payload["output_path"]
    assert Path(payload["output_path"]).is_file()
    Path(payload["output_path"]).unlink(missing_ok=True)


def test_doctor_strict_required_failure() -> None:
    result = runner.invoke(
        app,
        ["doctor", "--required", "not-a-provider", "--strict"],
    )
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["healthy_required"] is False
    assert payload["missing_required"] == ["not-a-provider"]


def test_mcp_rejects_unknown_transport() -> None:
    result = runner.invoke(app, ["mcp", "--transport", "socket"])
    assert result.exit_code == 1
    assert "stdio or streamable-http" in result.output


def test_managed_csharp_command_registered() -> None:
    result = runner.invoke(app, ["decompile-managed-csharp", "--help"])
    assert result.exit_code == 0
    assert "--type" in result.stdout


def test_environment_export_cli(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    evidence = tmp_path / "evidence.json"
    manifest.write_text(
        json.dumps(
            {
                "evidence_id": "ev_manifest",
                "normalized_result": {
                    "kind": "environment-manifest",
                    "parent_evidence_id": "ev_capture",
                    "name": "demo",
                    "tools": [
                        {
                            "name": "health",
                            "method": "GET",
                            "path_template": "/health",
                            "parameters": {},
                            "record_ordinals": [0],
                        }
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    evidence.write_text(
        json.dumps(
            {
                "evidence_id": "ev_capture",
                "normalized_result": {
                    "kind": "environment-capture",
                    "artifact": {"sha256": "a" * 64},
                    "entries": [
                        {
                            "request": {"method": "GET", "url": "https://x/health"},
                            "response": {
                                "status": 200,
                                "content": {"mimeType": "text/plain", "text": "ok"},
                            },
                        }
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "bundle"
    result = runner.invoke(
        app,
        ["environment-export", str(manifest), str(evidence), str(output)],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["status"] == "exported"
    assert (output / "envs/demo/Dockerfile").is_file()
    assert (output / "envs/demo/evidence.json").is_file()


def test_completions_cli() -> None:
    result = runner.invoke(app, ["completions", "bash"])
    assert result.exit_code == 0, result.output
    assert "_REA_COMPLETE" in result.stdout


def test_kuna_raw_image_cli(monkeypatch, tmp_path: Path) -> None:
    log = tmp_path / "kuna-args.txt"
    script = tmp_path / "kuna"
    script.write_text(
        '#!/bin/sh\nprintf \'%s\\n\' "$@" > "$KUNA_ARGS_LOG"\n'
        'echo \'[{"name":"main","address_hex":"0x1000"}]\'\n',
        encoding="utf-8",
    )
    script.chmod(0o755)
    raw = tmp_path / "firmware.bin"
    raw.write_bytes(b"\x90" * 32)
    monkeypatch.setenv("REA_KUNA_COMMAND", str(script))
    monkeypatch.setenv("KUNA_ARGS_LOG", str(log))
    result = runner.invoke(
        app,
        [
            "list-procedures",
            str(raw),
            "--raw-image",
            "--target",
            "x86:LE:64:default",
            "--base",
            "0x100000000",
            "--entry",
            "0x100000010",
            "--provider",
            "kuna",
        ],
    )
    assert result.exit_code == 0, result.output
    arguments = log.read_text(encoding="utf-8").splitlines()
    assert "--raw-image" in arguments
    assert arguments[arguments.index("--target") + 1] == "x86:LE:64:default"
    assert arguments[arguments.index("--entry") + 1] == "0x100000010"


def test_completions_rejects_unknown_shell() -> None:
    result = runner.invoke(app, ["completions", "tcsh"])
    assert result.exit_code == 2
    assert "unsupported shell" in result.output


def test_environment_export_rejects_manifest_parent_mismatch(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    evidence = tmp_path / "evidence.json"
    manifest.write_text(
        json.dumps(
            {
                "evidence_id": "ev_manifest",
                "normalized_result": {
                    "kind": "environment-manifest",
                    "parent_evidence_id": "ev_other",
                    "name": "demo",
                    "tools": [],
                },
            }
        ),
        encoding="utf-8",
    )
    evidence.write_text(
        json.dumps(
            {
                "evidence_id": "ev_capture",
                "normalized_result": {"kind": "environment-capture", "entries": []},
            }
        ),
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        ["environment-export", str(manifest), str(evidence), str(tmp_path / "bundle")],
    )
    assert result.exit_code != 0
    assert "parent Evidence" in result.output
