from __future__ import annotations

import json
from pathlib import Path

from rea_mcp.application.environment.bundle import (
    bundle_dockerfile,
    plan_environment_bundle,
    validate_bundle_name,
    write_environment_bundle,
)


def test_bundle_name_validation() -> None:
    assert validate_bundle_name("powerbi-demo").ok
    assert not validate_bundle_name("PowerBI Demo").ok
    assert not validate_bundle_name("con").ok


def test_dockerfile_pins_listener_and_install() -> None:
    text = bundle_dockerfile({"kind": "registry", "specifier": "rea-agents@6.7.0"})
    assert "MCP_HOST=0.0.0.0" in text
    assert "MCP_PORT=18765" in text
    assert "npm install -g" in text
    assert "rea-agents@6.7.0" in text


def test_plan_and_write_bundle(tmp_path: Path) -> None:
    plan = plan_environment_bundle(
        {"name": "demo"},
        tool_count=3,
        state={"served": False, "reason": "replay-only"},
        check={"tool": "get_status", "status": 200, "recordOrdinal": 4},
    )
    assert plan.ok
    data = plan.value
    assert len(data.files) == 5
    assert data.files[2].path == "envs/demo/Dockerfile"
    written = write_environment_bundle(
        data,
        tmp_path / "bundle",
        manifest_bytes=b'{"name":"demo"}',
        evidence_bytes=b'{"records":[]}',
    )
    assert written.ok
    root = tmp_path / "bundle"
    assert (root / "envs/demo/manifest.json").read_bytes() == b'{"name":"demo"}'
    assert (root / "tasks/smoke.json").is_file()
    assert json.loads((root / "tasks/smoke.json").read_text())[0]["env_id"] == "demo"


def test_write_refuses_non_empty_destination(tmp_path: Path) -> None:
    plan = plan_environment_bundle({"name": "demo"})
    assert plan.ok
    root = tmp_path / "bundle"
    root.mkdir()
    (root / "x").write_text("x")
    assert not write_environment_bundle(
        plan.value, root, manifest_bytes=b"{}", evidence_bytes=b"{}"
    ).ok
