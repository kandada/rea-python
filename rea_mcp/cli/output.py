"""CLI output and exit-status helpers."""

from __future__ import annotations

import json
import sys
from typing import Any, NoReturn

from ..domain.analysis_error import AnalysisError, project_analysis_error

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_SIGINT = 130


def is_tty() -> bool:
    return sys.stdout.isatty()


def emit_json(payload: Any, *, force: bool = False) -> None:
    """Write JSON indented on a terminal, compact when piped (smaller for agents)."""

    if force or is_tty():
        text = json.dumps(payload, indent=2, ensure_ascii=False)
    else:
        text = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    sys.stdout.write(text + "\n")


def emit_error(error: AnalysisError) -> None:
    sys.stderr.write(json.dumps(project_analysis_error(error), ensure_ascii=False) + "\n")


def fail(error: AnalysisError, *, code: int = EXIT_FAILURE) -> NoReturn:
    emit_error(error)
    raise SystemExit(code)


__all__ = ["EXIT_FAILURE", "EXIT_OK", "EXIT_SIGINT", "emit_error", "emit_json", "fail", "is_tty"]
