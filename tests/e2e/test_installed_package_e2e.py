"""Acceptance: build the wheel, install it, and run the installed package."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from tests.e2e.harness import REPO_ROOT

pytestmark = pytest.mark.acceptance


def _run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, **kwargs)  # type: ignore[arg-type]


def test_installed_wheel_runs_cli(tmp_path: Path, elf_file: Path) -> None:
    dist = tmp_path / "dist"
    build = _run(
        [sys.executable, "-m", "pip", "wheel", ".", "--no-deps", "-w", str(dist)],
        cwd=str(REPO_ROOT),
        timeout=300,
    )
    assert build.returncode == 0, build.stderr
    wheels = list(dist.glob("*.whl"))
    assert wheels, "no wheel built"
    wheel = wheels[0]

    names = zipfile.ZipFile(wheel).namelist()
    assert any("entry_points.txt" in name for name in names)
    assert not any(name.startswith("tests/") for name in names)
    assert not any(name.startswith("vendor/") for name in names)

    site = tmp_path / "site"
    install = _run(
        [sys.executable, "-m", "pip", "install", "--no-deps", "--target", str(site), str(wheel)],
        timeout=300,
    )
    assert install.returncode == 0, install.stderr

    env = dict(os.environ)
    env["PYTHONPATH"] = str(site)
    env.pop("REA_ANALYSIS_PROVIDER", None)

    providers = _run(
        [sys.executable, "-m", "rea_mcp", "providers"], cwd=str(tmp_path), env=env, timeout=120
    )
    assert providers.returncode == 0, providers.stderr
    payload = json.loads(providers.stdout)
    assert any(entry["id"] == "binary-layout" for entry in payload["providers"])

    inspect = _run(
        [sys.executable, "-m", "rea_mcp", "inspect-binary-layout", str(elf_file)],
        cwd=str(tmp_path),
        env=env,
        timeout=120,
    )
    assert inspect.returncode == 0, inspect.stderr
    assert json.loads(inspect.stdout)["evidence_id"].startswith("ev_")
