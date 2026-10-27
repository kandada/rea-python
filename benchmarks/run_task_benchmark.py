#!/usr/bin/env python3
"""Run bounded, reproducible CLI task benchmarks.

This does not call an LLM. It measures the cost of the exact command sequence a
skill would prescribe: turns, subprocess wall time, output tokens, and whether
required JSON facts are present.

Example:
    python benchmarks/run_task_benchmark.py --target native=/bin/ls
    python benchmarks/run_task_benchmark.py --tasks benchmarks/tasks.example.json --json
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _tokens(text: str) -> int:
    try:
        import tiktoken

        return len(tiktoken.get_encoding("cl100k_base").encode(text))
    except Exception:
        return max(1, len(text) // 4)


def _flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    result: dict[str, Any] = {}
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            result[path] = item
            result.update(_flatten(item, path))
    elif isinstance(value, list):
        for index, item in enumerate(value[:20]):
            result.update(_flatten(item, f"{prefix}[{index}]"))
    return result


def _has_required(payload: dict[str, Any], required: list[str]) -> bool:
    flat = _flatten(payload)
    for path in required:
        if path in flat:
            continue
        if any(key.endswith("." + path) or key == path for key in flat):
            continue
        if path not in json.dumps(payload, ensure_ascii=False):
            return False
    return True


def run_task(task: dict[str, Any], target: str | None, *, timeout: float = 120.0) -> dict[str, Any]:
    commands = task.get("commands") or []
    env = dict(os.environ)
    env.setdefault("REA_MCP_TOOLSET", str(task.get("toolset") or "core"))
    env.setdefault("REA_MCP_CLIENT", str(task.get("client") or "opencode"))
    started = time.monotonic()
    outputs: list[dict[str, Any]] = []
    turns = 0
    for command in commands:
        if not isinstance(command, list):
            continue
        command_args = [str(item) for item in command]
        if target:
            if "{target}" in command_args:
                command_args = [target if item == "{target}" else item for item in command_args]
                target_inserted = True
            else:
                target_inserted = False
        else:
            target_inserted = True
        if not target_inserted and command_args:
            command_args = [command_args[0], target, *command_args[1:]]
        argv = [sys.executable, "-m", "rea_mcp", *command_args]
        proc = subprocess.run(
            argv,
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        turns += 1
        try:
            parsed = json.loads(proc.stdout) if proc.stdout.strip() else None
        except json.JSONDecodeError:
            parsed = None
        outputs.append(
            {
                "command": command,
                "exit_code": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr[-1000:],
                "parsed": parsed,
            }
        )
    elapsed = time.monotonic() - started
    text = "\n".join(item["stdout"] for item in outputs)
    required = [str(item) for item in task.get("required") or []]
    success = all(item["exit_code"] == 0 for item in outputs)
    if required:
        success = success and _has_required(
            {"outputs": [item["parsed"] for item in outputs]}, required
        )
    return {
        "id": task.get("id"),
        "target": target,
        "commands": commands,
        "turns": turns,
        "elapsed_seconds": round(elapsed, 3),
        "tokens": _tokens(text),
        "bytes": len(text.encode("utf-8")),
        "success": success,
        "outputs": outputs,
    }


def run_tasks(tasks: list[dict[str, Any]], targets: dict[str, str]) -> dict[str, Any]:
    rows = []
    for task in tasks:
        target_key = str(task.get("target_key") or task.get("id") or "")
        target = targets.get(target_key) or task.get("target")
        if not target or not Path(str(target)).exists():
            rows.append(
                {
                    "id": task.get("id"),
                    "skipped": True,
                    "reason": f"target unavailable: {target_key}",
                }
            )
            continue
        rows.append(run_task(task, str(target)))
    passed = sum(1 for row in rows if row.get("success") is True)
    available = [row for row in rows if not row.get("skipped")]
    return {
        "task_count": len(rows),
        "executed": len(available),
        "passed": passed,
        "turns": sum(int(row.get("turns") or 0) for row in available),
        "tokens": sum(int(row.get("tokens") or 0) for row in available),
        "elapsed_seconds": round(
            sum(float(row.get("elapsed_seconds") or 0) for row in available), 3
        ),
        "tasks": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tasks", default=str(ROOT / "benchmarks" / "tasks.example.json"))
    parser.add_argument("--target", action="append", default=[], help="id=path")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    targets: dict[str, str] = {}
    for item in args.target:
        key, separator, value = item.partition("=")
        if separator:
            targets[key] = value
    tasks = json.loads(Path(args.tasks).read_text(encoding="utf-8"))
    report = run_tasks(tasks, targets)
    if args.json:
        print(json.dumps(report, indent=2))
        return
    print(
        f"tasks={report['task_count']} executed={report['executed']} "
        f"passed={report['passed']} turns={report['turns']} "
        f"tokens={report['tokens']} seconds={report['elapsed_seconds']}"
    )
    for row in report["tasks"]:
        if row.get("skipped"):
            print(f"- {row['id']}: skipped ({row['reason']})")
        else:
            print(
                f"- {row['id']}: success={row['success']} turns={row['turns']} "
                f"tokens={row['tokens']} seconds={row['elapsed_seconds']}"
            )


if __name__ == "__main__":
    main()
