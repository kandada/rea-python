"""Coding-agent adapters for the build phase."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ...domain.analysis_error import AnalysisError, AnalysisInputError
from ...domain.project import ProjectUsage
from ...domain.result import Result, err, ok
from ..project_store import ProjectStore
from .api_builder import api_configured, run_api_builder

_KNOWN: dict[str, tuple[str, str]] = {
    "aacode": ("aacode", "prompt"),
    "opencode": ("opencode", "run"),
    "claude": ("claude", "-p"),
    "codex": ("codex", "exec"),
    "dsh": ("dsh", "--profile headless"),
}


@dataclass
class BuilderAdapter:
    name: str
    command: list[str]
    stdin_prompt: bool = False


def _env_command() -> BuilderAdapter | None:
    configured = os.environ.get("REA_CRAFT_BUILDER_COMMAND")
    if not configured:
        return None
    try:
        parts = shlex.split(configured)
    except ValueError:
        return None
    if not parts:
        return None
    if any("{prompt}" in part for part in parts):
        return BuilderAdapter("custom", parts)
    return BuilderAdapter("custom", [*parts, "{prompt}"])


def detect_builders() -> list[str]:
    if _env_command() is not None:
        return ["custom"]
    found = ["deepseek-api"] if api_configured() else []
    for name, (program, _arg) in _KNOWN.items():
        if shutil.which(program):
            found.append(name)
    return found


def resolve_builder(name: str | None = None) -> Result[BuilderAdapter, AnalysisError]:
    custom = _env_command()
    if custom is not None and (not name or name == "custom"):
        return ok(custom)
    selected = (name or os.environ.get("REA_CRAFT_BUILDER") or "").strip()
    if not selected:
        found = detect_builders()
        selected = found[0] if found else ""
    if selected in _KNOWN:
        program, arg = _KNOWN[selected]
        if shutil.which(program) is None:
            return err(
                AnalysisInputError(
                    operation="craft-build", message=f"builder {selected} is not on PATH"
                )
            )
        if selected == "dsh":
            return ok(BuilderAdapter(selected, [program, *shlex.split(arg)], stdin_prompt=True))
        return ok(BuilderAdapter(selected, [program, *shlex.split(arg), "{prompt}"]))
    if selected:
        try:
            parts = shlex.split(selected)
        except ValueError:
            return err(
                AnalysisInputError(
                    operation="craft-build", message=f"builder command is malformed: {selected}"
                )
            )
        if parts:
            return ok(
                BuilderAdapter(
                    Path(parts[0]).name,
                    parts if any("{prompt}" in item for item in parts) else [*parts, "{prompt}"],
                )
            )
    return err(
        AnalysisInputError(
            operation="craft-build",
            message="no coding-agent builder found; set REA_CRAFT_BUILDER/REA_CRAFT_BUILDER_COMMAND",
        )
    )


def detect_builders_commands() -> list[str]:
    if _env_command() is not None:
        return ["custom"]
    return [name for name in _KNOWN if shutil.which(_KNOWN[name][0])]


def _prompt_for(store: ProjectStore, failures: list[str] | None) -> str:
    brief = store.read_text("investigation/brief.md") or ""
    lines = [brief, "", "## Project", "", f"Folder: {store.root}", f"App folder: {store.app_dir}"]
    if failures:
        lines.extend(["", "## Previous check failures", ""])
        lines.extend(f"- {item}" for item in failures)
    stack = (store.manifest.stack or "").lower()
    if "unity" in stack:
        lines.extend(
            [
                "",
                "## Unity recipe",
                "Create Assets/, Packages/manifest.json and ProjectSettings/ProjectVersion.txt.",
                "Write C# under Assets/Scripts/. Add Assets/Editor/CraftBuild.cs with a static Build()",
                "that creates scenes, adds them to build settings and calls BuildPipeline.BuildPlayer",
                "to app/Build/Game.app (macOS) or app/Build/Game.exe (Windows); EditorApplication.Exit(1)",
                "on failure. Build with the Unity editor in batchmode -executeMethod CraftBuild.Build.",
            ]
        )
    elif "unreal" in stack:
        lines.extend(
            [
                "",
                "## Unreal recipe",
                "Create a .uproject, Config/, Source/ and Content/. Build and cook to app/Build with",
                "RunUAT BuildCookRun -build -cook -stage -pak -archive -unattended.",
            ]
        )
    elif "godot" in stack:
        lines.extend(
            [
                "",
                "## Godot recipe",
                "Create project.godot and the scenes/scripts. Run the Godot editor headlessly with",
                "--import, then add app/self-test.json with move/act/hud steps.",
            ]
        )
    lines.extend(
        [
            "",
            "Work in the app folder. Do not modify project.json, investigation/, capture/ or checks/.",
            "When finished, print a short summary of what you built and how to run it.",
        ]
    )
    return "\n".join(lines)


def run_builder(
    store: ProjectStore,
    *,
    builder: str | None = None,
    round_number: int = 1,
    failures: list[str] | None = None,
    timeout: float = 1800.0,
) -> Result[dict[str, Any], AnalysisError]:
    selected = (builder or os.environ.get("REA_CRAFT_BUILDER") or "").strip()
    if selected in ("deepseek-api", "deepseek", "api") or (
        not selected and api_configured() and not detect_builders_commands()
    ):
        return run_api_builder(
            store, prompt=_prompt_for(store, failures), round_number=round_number
        )
    adapter = resolve_builder(builder)
    if not adapter.ok:
        return err(adapter.error)
    store.app_dir.mkdir(parents=True, exist_ok=True)
    prompt = _prompt_for(store, failures)
    store.write_text(f"builds/round-{round_number:04d}/prompt.md", prompt)
    command = [prompt if part == "{prompt}" else part for part in adapter.value.command]
    started = time.monotonic()
    try:
        process = subprocess.run(
            command,
            cwd=str(store.app_dir),
            input=prompt if adapter.value.stdin_prompt else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={
                **os.environ,
                "REA_CRAFT_PROJECT": str(store.root),
                "REA_CRAFT_CAPTURE": str(store.capture_dir),
            },
        )
    except (OSError, subprocess.TimeoutExpired) as cause:
        return err(AnalysisInputError(operation="craft-build", message=str(cause)))
    elapsed = time.monotonic() - started
    output = (process.stdout or "") + (process.stderr or "")
    store.write_json(
        f"builds/round-{round_number:04d}/builder.json",
        {
            "builder": adapter.value.name,
            "command": command[:2],
            "exit_code": process.returncode,
            "output": output[-12000:],
            "seconds": round(elapsed, 3),
        },
    )
    store.add_usage(ProjectUsage(turns=1, seconds=elapsed))
    store.journal(
        {
            "event": "build",
            "round": round_number,
            "builder": adapter.value.name,
            "exit_code": process.returncode,
        }
    )
    if process.returncode != 0:
        return err(
            AnalysisInputError(
                operation="craft-build",
                message=f"builder exited {process.returncode}: {output[-2000:]}",
            )
        )
    return ok(
        {
            "builder": adapter.value.name,
            "exit_code": process.returncode,
            "seconds": round(elapsed, 3),
            "output": output[-4000:],
        }
    )


__all__ = ["BuilderAdapter", "detect_builders", "resolve_builder", "run_builder"]
