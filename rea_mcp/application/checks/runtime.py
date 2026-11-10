"""Runtime smoke checks for app projects."""

from __future__ import annotations

import json
import subprocess
import time

from ...domain.check import CheckResult, Claim
from ..project_store import ProjectStore


def runtime_check(store: ProjectStore, round_number: int) -> CheckResult:
    manifest = store.app_dir / "runtime.json"
    if not manifest.is_file():
        return CheckResult(
            "runtime-smoke",
            round_number,
            False,
            "app/runtime.json is missing",
            unknowns=["runtime command manifest"],
        )
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        command = payload.get("command") if isinstance(payload, dict) else None
    except (OSError, ValueError) as cause:
        return CheckResult(
            "runtime-smoke", round_number, False, f"runtime.json is unreadable: {cause}"
        )
    if (
        not isinstance(command, list)
        or not command
        or not all(isinstance(item, str) for item in command)
    ):
        return CheckResult(
            "runtime-smoke", round_number, False, "runtime.json has no command array"
        )
    process = None
    try:
        process = subprocess.Popen(
            command,
            cwd=str(store.app_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        time.sleep(1.5)
        if process.poll() is None:
            return CheckResult(
                "runtime-smoke",
                round_number,
                True,
                "process started and stayed alive",
                claims=[Claim("runtime starts", True)],
            )
        output = (process.stdout.read() if process.stdout else "") + (
            process.stderr.read() if process.stderr else ""
        )
        passed = process.returncode == 0
        return CheckResult(
            "runtime-smoke",
            round_number,
            passed,
            "process exited 0"
            if passed
            else f"process exited {process.returncode}: {output[-1500:]}",
            claims=[Claim("runtime starts", passed, "" if passed else output[-500:])],
        )
    except (OSError, subprocess.TimeoutExpired) as cause:
        return CheckResult(
            "runtime-smoke", round_number, False, f"could not start runtime: {cause}"
        )
    finally:
        if process is not None and process.poll() is None:
            import contextlib
            import os
            import signal

            killpg = getattr(os, "killpg", None)
            sigterm = getattr(signal, "SIGTERM", signal.SIGTERM)
            sigkill = getattr(signal, "SIGKILL", sigterm)
            with contextlib.suppress(OSError):
                if killpg is not None:
                    killpg(process.pid, sigterm)
                else:
                    process.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=3)
            if process.poll() is None:
                with contextlib.suppress(OSError):
                    if killpg is not None:
                        killpg(process.pid, sigkill)
                    else:
                        process.kill()


__all__ = ["runtime_check"]
