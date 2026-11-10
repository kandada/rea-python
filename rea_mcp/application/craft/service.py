"""Headless Study → Build → Check → Refine orchestration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ...domain.analysis_error import AnalysisError, AnalysisInputError
from ...domain.check import CheckResult
from ...domain.policy import approval_for
from ...domain.project import project_slug
from ...domain.result import Result, err, ok
from ..checks.basic import run_checks
from ..project_store import ProjectStore, create_project
from .builders import detect_builders, run_builder
from .study import study_project


def _failures(checks: list[CheckResult]) -> list[str]:
    rows: list[str] = []
    for check in checks:
        if check.passed and check.good(90.0) and not check.unknowns:
            continue
        rows.append(f"{check.check}: {check.note}")
        rows.extend(f"{claim.title}: {claim.detail}" for claim in check.failed_claims())
        rows.extend(f"unknown: {item}" for item in check.unknowns)
    return rows


def _ready(checks: list[CheckResult], good_enough: float) -> bool:
    return bool(checks) and all(check.good(good_enough) for check in checks)


def create_craft(
    *,
    target: str | None,
    request: str,
    project_dir: str | Path | None = None,
    name: str | None = None,
    mode: str = "clean_room",
    stack: str = "",
    builder: str = "",
) -> Result[ProjectStore, AnalysisInputError]:
    label = name or project_slug(
        Path(target).name if target and not target.startswith("http") else (target or request)[:40]
    )
    root = Path(project_dir).expanduser() if project_dir else Path.cwd() / project_slug(label)
    return create_project(
        root,
        name=label,
        request=request,
        target=target,
        mode=mode,
        stack=stack,
        builder=builder,
    )


def study(
    store: ProjectStore, *, widths: list[int] | None = None
) -> Result[dict[str, Any], AnalysisError]:
    return study_project(store, widths=widths)


def build(
    store: ProjectStore,
    *,
    builder: str | None = None,
    round_number: int | None = None,
    failures: list[str] | None = None,
) -> Result[dict[str, Any], AnalysisError]:
    if approval_for(store.manifest, "commands") == "refuse":
        return err(
            AnalysisInputError(
                operation="craft-build",
                message="project policy refuses command execution; set commands to allow or ask",
            )
        )
    number = round_number if round_number is not None else max(1, store.next_round())
    store.manifest.touch(status="building", step="build")
    store.save_manifest()
    result = run_builder(
        store,
        builder=builder or store.manifest.builder or None,
        round_number=number,
        failures=failures,
    )
    if not result.ok:
        store.manifest.touch(status="failed", step="build")
        store.manifest.note = result.error.message
        store.save_manifest()
        return result
    return ok({"round": number, **result.value})


def check(
    store: ProjectStore,
    *,
    round_number: int | None = None,
    good_enough: float = 85.0,
) -> Result[list[CheckResult], AnalysisError]:
    number = round_number if round_number is not None else store.next_round()
    store.manifest.touch(status="checking", step="check")
    store.save_manifest()
    try:
        results = run_checks(store, number, good_enough=good_enough)
    except Exception as cause:
        store.manifest.touch(status="failed", step="check")
        store.manifest.note = str(cause)
        store.save_manifest()
        return err(AnalysisInputError(operation="craft-check", message=str(cause)))
    for result in results:
        store.save_check(result)
    ready = _ready(results, good_enough)
    store.manifest.status = "ready" if ready else "needs_you"
    store.manifest.step = "done" if ready else "check"
    store.manifest.note = "all checks are good enough" if ready else "checks found work still to do"
    store.manifest.touch()
    store.save_manifest()
    store.journal(
        {
            "event": "check",
            "round": number,
            "passed": ready,
            "checks": [result.to_dict() for result in results],
        }
    )
    return ok(results)


def run(
    *,
    target: str | None,
    request: str,
    project_dir: str | Path | None = None,
    name: str | None = None,
    mode: str = "clean_room",
    stack: str = "",
    builder: str | None = None,
    rounds: int = 3,
    good_enough: float = 85.0,
    widths: list[int] | None = None,
) -> Result[dict[str, Any], AnalysisError]:
    created = create_craft(
        target=target,
        request=request,
        project_dir=project_dir,
        name=name,
        mode=mode,
        stack=stack,
        builder=builder or "",
    )
    if not created.ok:
        return err(created.error)
    store = created.value
    studied = study(store, widths=widths)
    if not studied.ok:
        return err(studied.error)
    failures: list[str] = []
    history: list[dict[str, Any]] = []
    for number in range(1, max(1, rounds) + 1):
        built = build(
            store,
            builder=builder or store.manifest.builder or None,
            round_number=number,
            failures=failures,
        )
        if not built.ok:
            return err(built.error)
        checked = check(store, round_number=number, good_enough=good_enough)
        if not checked.ok:
            return err(checked.error)
        history.append(
            {
                "round": number,
                "build": built.value,
                "checks": [result.to_dict() for result in checked.value],
            }
        )
        if _ready(checked.value, good_enough):
            store.manifest.touch(status="ready", step="done")
            store.manifest.note = "all checks are good enough"
            store.save_manifest()
            return ok({"project": store.summary(), "rounds": history, "ready": True})
        failures = _failures(checked.value)
        if not failures:
            failures = ["checks did not pass"]
    store.manifest.touch(status="needs_you", step="check")
    store.manifest.note = "maximum rounds reached"
    store.save_manifest()
    return ok({"project": store.summary(), "rounds": history, "ready": False})


def project_status(store: ProjectStore) -> dict[str, Any]:
    return store.summary()


def ready(
    store: ProjectStore, *, good_enough: float = 85.0
) -> Result[dict[str, Any], AnalysisError]:
    checks = store.latest_checks()
    if not _ready(checks, good_enough):
        return err(
            AnalysisInputError(operation="craft-ready", message="latest checks are not good enough")
        )
    store.manifest.touch(status="ready", step="done")
    store.manifest.note = "all checks are good enough"
    store.save_manifest()
    return ok(store.summary())


__all__ = [
    "build",
    "check",
    "create_craft",
    "detect_builders",
    "project_status",
    "ready",
    "run",
    "study",
]
