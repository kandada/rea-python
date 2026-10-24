"""Owned child-process supervision.

REA-Python only cleans up processes it can prove it owns. Children are started in their
own process group/session so a timeout or cancellation can terminate the whole
group, and captured output is bounded so a chatty child cannot exhaust memory.
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ..domain.analysis_error import AnalysisCancelledError, AnalysisError
from ..domain.result import Result, err, ok

_POSIX = os.name == "posix"

DEFAULT_MAX_OUTPUT_BYTES = 64 * 1024


@dataclass
class ProcessResult:
    exit_code: int | None
    stdout: str
    stderr: str
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    timed_out: bool = False
    cancelled: bool = False
    limitations: list[str] = field(default_factory=list)


def run_owned_process(
    argv: Sequence[str],
    *,
    timeout: float | None = None,
    env: Mapping[str, str] | None = None,
    cwd: str | None = None,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    input_bytes: bytes | None = None,
    cancel_event: threading.Event | None = None,
    operation: str = "run_process",
) -> Result[ProcessResult, AnalysisError]:
    """Run a child in its own session and return a bounded observation."""

    if cancel_event is not None and cancel_event.is_set():
        return err(AnalysisCancelledError(operation=operation))
    try:
        process = subprocess.Popen(
            list(argv),
            cwd=cwd,
            env=None if env is None else dict(env),
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as cause:
        from ..domain.analysis_error import ProviderAdapterError

        return err(ProviderAdapterError(message=str(cause), details={"argv": list(argv)}))

    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    stdout_truncated = False
    stderr_truncated = False

    def pump(stream: Any, sink: list[bytes], *, name: str) -> None:
        nonlocal stdout_truncated, stderr_truncated
        total = 0
        while True:
            chunk = stream.read(4096)
            if not chunk:
                break
            total += len(chunk)
            if total <= max_output_bytes:
                sink.append(chunk)
            elif name == "stdout":
                stdout_truncated = True
            else:
                stderr_truncated = True

    stdout_thread = threading.Thread(
        target=pump, args=(process.stdout, stdout_chunks), kwargs={"name": "stdout"}, daemon=True
    )
    stderr_thread = threading.Thread(
        target=pump, args=(process.stderr, stderr_chunks), kwargs={"name": "stderr"}, daemon=True
    )
    stdout_thread.start()
    stderr_thread.start()

    if input_bytes is not None and process.stdin is not None:
        try:
            process.stdin.write(input_bytes)
            process.stdin.close()
        except (BrokenPipeError, OSError):
            pass

    timed_out = False
    cancelled = False
    deadline = None if timeout is None else time.monotonic() + timeout
    while True:
        if cancel_event is not None and cancel_event.is_set():
            cancelled = True
            _terminate_group(process)
            break
        remaining = None if deadline is None else deadline - time.monotonic()
        if remaining is not None and remaining <= 0:
            timed_out = True
            _terminate_group(process)
            break
        try:
            process.wait(timeout=0.1 if remaining is None else min(0.1, remaining))
            break
        except subprocess.TimeoutExpired:
            continue

    stdout_thread.join(timeout=5)
    stderr_thread.join(timeout=5)

    exit_code = process.returncode
    result = ProcessResult(
        exit_code=exit_code,
        stdout=_decode(b"".join(stdout_chunks)),
        stderr=_decode(b"".join(stderr_chunks)),
        stdout_truncated=stdout_truncated,
        stderr_truncated=stderr_truncated,
        timed_out=timed_out,
    )
    if timed_out:
        result.limitations.append(f"Process exceeded its {timeout}s deadline and was terminated.")
    if cancelled:
        return err(
            AnalysisCancelledError(
                operation=operation,
                details={
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "timed_out": timed_out,
                    "partial": True,
                },
            )
        )
    return ok(result)


def _kill_group(pid: int, signal_number: int) -> None:
    killpg = getattr(os, "killpg", None)
    getpgid = getattr(os, "getpgid", None)
    if killpg is None or getpgid is None:
        raise OSError("process groups are unavailable")
    killpg(getpgid(pid), signal_number)


def _terminate_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if not _POSIX:
        _terminate_process(process)
        return
    try:
        _kill_group(process.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            _kill_group(process.pid, getattr(signal, "SIGKILL", signal.SIGTERM))
        except (ProcessLookupError, PermissionError, OSError):
            process.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=5)


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=5)


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


__all__ = ["DEFAULT_MAX_OUTPUT_BYTES", "ProcessResult", "run_owned_process"]
