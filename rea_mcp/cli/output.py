"""CLI output and exit-status helpers."""

from __future__ import annotations

import contextvars
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, NoReturn

from ..domain.analysis_error import AnalysisError, project_analysis_error

_OUTPUT_BUDGET: contextvars.ContextVar[int] = contextvars.ContextVar(
    "rea_cli_output_budget", default=0
)


def set_output_budget(budget: int) -> None:
    _OUTPUT_BUDGET.set(max(0, budget))


EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_SIGINT = 130


def is_tty() -> bool:
    return sys.stdout.isatty()


def _summary(payload: Any) -> dict[str, Any]:
    if isinstance(payload, dict):
        from ..application.analysis_view import summarize_bundle, summarize_record

        if "records" in payload:
            return summarize_bundle(payload)
        if "evidence_id" in payload and "normalized_result" in payload:
            normalized = payload.get("normalized_result")
            if isinstance(normalized, dict) and "reported_counts" in normalized:
                from ..providers.formats.managed_inspection import (
                    summarize_managed_inspection,
                )

                return summarize_managed_inspection(normalized)
            return summarize_record(payload)
        return {"keys": sorted(str(key) for key in payload)}
    return {"type": type(payload).__name__}


def emit_json(payload: Any, *, force: bool = False) -> None:
    """Write JSON indented on a terminal, compact when piped (smaller for agents)."""

    pretty = force or is_tty()
    if pretty:
        text = json.dumps(payload, indent=2, ensure_ascii=False)
    else:
        text = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    budget = _OUTPUT_BUDGET.get()
    encoded = text.encode("utf-8")
    if budget > 0 and len(encoded) > budget:
        digest = hashlib.sha256(encoded).hexdigest()[:12]
        destination = Path(tempfile.gettempdir()) / f"rea-cli-{os.getpid()}-{digest}.json"
        try:
            destination.write_bytes(encoded)
        except OSError:
            destination = Path.cwd() / f"rea-cli-{os.getpid()}-{digest}.json"
            destination.write_bytes(encoded)
        payload = {
            "truncated": True,
            "reason": "cli_response_budget",
            "budget_bytes": budget,
            "result_bytes": len(encoded),
            "output_path": str(destination),
            "summary": _summary(payload),
        }
        text = json.dumps(
            payload,
            indent=2 if pretty else None,
            ensure_ascii=False,
            separators=None if pretty else (",", ":"),
        )
        encoded = text.encode("utf-8")
    try:
        sys.stdout.write(text + "\n")
        sys.stdout.flush()
    except BrokenPipeError:
        # The reader closed the pipe (e.g. `| head`). Silence the interpreter's
        # shutdown error and exit with the conventional SIGPIPE status.
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except OSError:
            pass
        raise SystemExit(141) from None


def emit_error(error: AnalysisError) -> None:
    sys.stderr.write(json.dumps(project_analysis_error(error), ensure_ascii=False) + "\n")


def fail(error: AnalysisError, *, code: int = EXIT_FAILURE) -> NoReturn:
    emit_error(error)
    raise SystemExit(code)


__all__ = [
    "EXIT_FAILURE",
    "EXIT_OK",
    "EXIT_SIGINT",
    "emit_error",
    "emit_json",
    "fail",
    "is_tty",
    "set_output_budget",
]
