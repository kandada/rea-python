"""Process capture: run a command and record bounded runtime observations."""

from __future__ import annotations

from typing import Any

from ..domain.analysis_error import AnalysisError
from ..domain.result import Result, err, ok
from ..process.supervision import ProcessResult, run_owned_process


def capture_process(
    command: list[str],
    *,
    timeout: float = 30.0,
    cwd: str | None = None,
) -> Result[dict[str, Any], AnalysisError]:
    """Run a command in its own session and return a bounded observation."""

    result = run_owned_process(
        command, timeout=timeout, cwd=cwd, operation="capture_process", cancel_event=None
    )
    if not result.ok:
        return err(result.error)
    return ok(_project(result.value, command))


def _project(observed: ProcessResult, command: list[str]) -> dict[str, Any]:
    return {
        "command": list(command),
        "exit_code": observed.exit_code,
        "stdout": observed.stdout,
        "stderr": observed.stderr,
        "stdout_truncated": observed.stdout_truncated,
        "stderr_truncated": observed.stderr_truncated,
        "timed_out": observed.timed_out,
        "limitations": list(observed.limitations),
    }


__all__ = ["capture_process"]
