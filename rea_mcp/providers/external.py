"""Helpers for providers backed by caller-supplied external tools.

REA-Python never installs or bundles these engines. A provider reports an actionable
unavailability reason when its tool is missing, and runs only when the caller has
supplied a compatible executable (on ``PATH`` or via a ``REA_*`` environment
variable).
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ToolResolution:
    available: bool
    path: str | None
    reason: str | None


def resolve_tool(names: tuple[str, ...], env_var: str | None = None) -> ToolResolution:
    """Resolve a tool from an explicit env path or from ``PATH``."""

    if env_var is not None:
        configured = os.environ.get(env_var)
        if configured:
            if os.access(configured, os.X_OK) and Path(configured).is_file():
                return ToolResolution(True, configured, None)
            return ToolResolution(
                False, None, f"{env_var} is set to {configured!r} but is not an executable file"
            )
    for name in names:
        found = shutil.which(name)
        if found is not None:
            return ToolResolution(True, found, None)
    first = names[0] if names else "tool"
    return ToolResolution(
        False,
        None,
        f"{first} was not found on PATH; supply it via {env_var or 'an absolute path'}",
    )


def resolve_shell_command(command: str) -> ToolResolution:
    """Resolve a caller-supplied shell command string (first token on PATH or absolute)."""

    first = command.split()[0] if command.strip() else ""
    if not first:
        return ToolResolution(False, None, "No command configured")
    if os.path.isabs(first) and os.access(first, os.X_OK):
        return ToolResolution(True, command, None)
    found = shutil.which(first)
    if found is not None:
        return ToolResolution(True, command, None)
    return ToolResolution(False, None, f"{first} was not found on PATH")


def optional_import(module: str) -> Any:
    """Import an optional dependency without failing the package import."""

    try:
        return __import__(module)
    except ImportError:
        return None


__all__ = ["ToolResolution", "optional_import", "resolve_shell_command", "resolve_tool"]
