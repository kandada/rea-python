"""Environment replay check for craft projects."""

from __future__ import annotations

import json

from ...domain.check import CheckResult, Claim
from ..environment.compare import compare_environment
from ..environment.source import load_environment_source, load_probe_exchanges
from ..project_store import ProjectStore


def environment_check(store: ProjectStore, round_number: int) -> CheckResult:
    directory = store.capture_dir / "environment"
    manifest_path = directory / "manifest.json"
    evidence_path = directory / "evidence.json"
    if not manifest_path.is_file() or not evidence_path.is_file():
        return CheckResult(
            "environment",
            round_number,
            False,
            "environment capture is missing",
            unknowns=["capture/environment/manifest.json or evidence.json"],
        )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as cause:
        return CheckResult(
            "environment", round_number, False, f"environment files are unreadable: {cause}"
        )
    loaded = load_environment_source(manifest, evidence)
    if not loaded.ok:
        return CheckResult("environment", round_number, False, loaded.error.message)
    probe_path = store.app_dir / "environment.json"
    if not probe_path.is_file():
        return CheckResult(
            "environment",
            round_number,
            False,
            "app/environment.json is missing",
            unknowns=["probe capture"],
        )
    try:
        probes = load_probe_exchanges(json.loads(probe_path.read_text(encoding="utf-8")))
    except (OSError, ValueError) as cause:
        return CheckResult("environment", round_number, False, f"probe is unreadable: {cause}")
    if not probes:
        return CheckResult("environment", round_number, False, "probe has no exchanges")
    result = compare_environment(loaded.value, probes)
    coverage = result.get("coverage") or {}
    unchanged = result.get("status") == "unchanged"
    complete = coverage.get("state") == "complete"
    claims = [
        Claim("all probes match", unchanged, f"status={result.get('status')}"),
        Claim("probe coverage complete", complete, f"state={coverage.get('state')}"),
    ]
    return CheckResult(
        "environment",
        round_number,
        unchanged and complete,
        f"{result.get('probe_count')} probes; status={result.get('status')}",
        claims=claims,
        artifacts=[str(probe_path)],
    )


__all__ = ["environment_check"]
