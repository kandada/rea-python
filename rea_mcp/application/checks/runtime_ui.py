"""Best-effort native window check for app projects."""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import time

from ...domain.check import CheckResult, Claim
from ..project_store import ProjectStore


def _window_titles(pid: int) -> tuple[list[str], str | None]:
    if os.name == "nt":
        powershell = shutil.which("powershell") or shutil.which("pwsh")
        if powershell is None:
            return [], "PowerShell is unavailable"
        script = f"(Get-Process -Id {pid} -ErrorAction SilentlyContinue).MainWindowTitle"
        try:
            result = subprocess.run(
                [powershell, "-NoProfile", "-Command", script],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired) as cause:
            return [], str(cause)
        title = result.stdout.strip()
        return ([title] if title else []), None
    osascript = shutil.which("osascript")
    if osascript is None:
        return [], "osascript is unavailable"
    script = (
        f'tell application "System Events" to get name of every window of '
        f"(first process whose unix id is {pid})"
    )
    try:
        result = subprocess.run(
            [osascript, "-e", script], capture_output=True, text=True, timeout=10
        )
    except (OSError, subprocess.TimeoutExpired) as cause:
        return [], str(cause)
    if result.returncode != 0:
        return [], (result.stderr or "window inspection was refused").strip()[-500:]
    return [item.strip() for item in result.stdout.split(",") if item.strip()], None


def _ui_labels(pid: int) -> tuple[list[str], str | None]:
    if os.name == "nt":
        powershell = shutil.which("powershell") or shutil.which("pwsh")
        if powershell is None:
            return [], "PowerShell is unavailable"
        script = (
            "Add-Type -AssemblyName UIAutomationClient; "
            f"$p=Get-Process -Id {pid} -ErrorAction SilentlyContinue; "
            "if(-not $p){exit 1}; "
            "$root=[System.Windows.Automation.AutomationElement]::RootElement; "
            "$cond=New-Object System.Windows.Automation.PropertyCondition("
            "[System.Windows.Automation.AutomationElement]::ProcessIdProperty,"
            f"{pid}); "
            "$w=$root.FindFirst([System.Windows.Automation.TreeScope]::Children,$cond); "
            "if(-not $w){exit 2}; "
            "$all=$w.FindAll([System.Windows.Automation.TreeScope]::Descendants,"
            "[System.Windows.Automation.Condition]::TrueCondition); "
            "$all | ForEach-Object { $_.Current.Name } | Where-Object { $_ }"
        )
        try:
            result = subprocess.run(
                [powershell, "-NoProfile", "-Command", script],
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired) as cause:
            return [], str(cause)
        if result.returncode != 0:
            return [], (result.stderr or "UI Automation was refused").strip()[-500:]
        return [item.strip() for item in result.stdout.splitlines() if item.strip()], None
    osascript = shutil.which("osascript")
    if osascript is None:
        return [], "osascript is unavailable"
    script = (
        f'tell application "System Events" to tell (first process whose unix id is {pid})\n'
        "set out to {}\n"
        "repeat with w in windows\n"
        "repeat with e in entire contents of w\n"
        "try\n"
        "set end of out to (name of e as text)\n"
        "end try\n"
        "end repeat\n"
        "end repeat\n"
        "set text item delimiters to linefeed\n"
        "return out as text\n"
        "end tell"
    )
    try:
        result = subprocess.run(
            [osascript, "-e", script], capture_output=True, text=True, timeout=15
        )
    except (OSError, subprocess.TimeoutExpired) as cause:
        return [], str(cause)
    if result.returncode != 0:
        return [], (result.stderr or "UI inspection was refused").strip()[-500:]
    return [item.strip() for item in result.stdout.splitlines() if item.strip()], None


def runtime_ui_check(store: ProjectStore, round_number: int) -> CheckResult:
    manifest = store.app_dir / "runtime.json"
    if not manifest.is_file():
        return CheckResult(
            "runtime-ui",
            round_number,
            False,
            "app/runtime.json is missing",
            unknowns=["runtime manifest"],
        )
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError) as cause:
        return CheckResult(
            "runtime-ui", round_number, False, f"runtime.json is unreadable: {cause}"
        )
    command = payload.get("command") if isinstance(payload, dict) else None
    if (
        not isinstance(command, list)
        or not command
        or not all(isinstance(item, str) for item in command)
    ):
        return CheckResult("runtime-ui", round_number, False, "runtime.json has no command array")
    expected = str(payload.get("window_title") or "")
    expected_labels = payload.get("ui_labels")
    process = None
    try:
        process = subprocess.Popen(
            command,
            cwd=str(store.app_dir),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        time.sleep(2.0)
        if process.poll() is not None:
            return CheckResult(
                "runtime-ui",
                round_number,
                False,
                f"runtime exited before a window was inspected (code {process.returncode})",
            )
        titles, error = _window_titles(process.pid)
        labels: list[str] = []
        label_error: str | None = None
        if isinstance(expected_labels, list) and expected_labels:
            labels, label_error = _ui_labels(process.pid)
        if error is not None:
            return CheckResult(
                "runtime-ui",
                round_number,
                False,
                f"window inspection unavailable: {error}",
                unknowns=["native window inspection"],
            )
        claims = [Claim("window is visible", bool(titles), "no window title")]
        if expected:
            claims.append(
                Claim(
                    "window title matches",
                    any(expected in title for title in titles),
                    f"expected {expected!r}, saw {titles!r}",
                )
            )
        if isinstance(expected_labels, list) and expected_labels:
            if label_error is not None:
                claims.append(Claim("UI labels are readable", False, label_error))
            else:
                haystack = " | ".join(labels).lower()
                for label in expected_labels[:50]:
                    text = str(label)
                    claims.append(
                        Claim(
                            f"UI contains {text!r}",
                            text.lower() in haystack,
                            f"saw {labels[:30]!r}",
                        )
                    )
        passed = all(claim.passed for claim in claims)
        return CheckResult(
            "runtime-ui",
            round_number,
            passed,
            f"windows: {titles!r}",
            claims=claims,
        )
    except (OSError, subprocess.TimeoutExpired) as cause:
        return CheckResult("runtime-ui", round_number, False, f"could not start runtime: {cause}")
    finally:
        if process is not None and process.poll() is None:
            killpg = getattr(os, "killpg", None)
            sigterm = getattr(signal, "SIGTERM", signal.SIGTERM)
            sigkill = getattr(signal, "SIGKILL", sigterm)
            try:
                if killpg is not None:
                    killpg(process.pid, sigterm)
                else:
                    process.terminate()
            except OSError:
                process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    if killpg is not None:
                        killpg(process.pid, sigkill)
                    else:
                        process.kill()
                except OSError:
                    process.kill()


__all__ = ["runtime_ui_check"]
