"""Agent/client setup plan and MCP server registration.

Setup is additive and idempotent: it plans changes, and a write only happens when
the caller supplies a destination. Existing files are backed up before rewrite.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.result import Result, err, ok

# Informational locations for common MCP-capable clients.
KNOWN_CLIENT_CONFIGS: tuple[str, ...] = (
    "~/Library/Application Support/Claude/claude_desktop_config.json",
    "~/.config/Code/User/globalStorage/mcp.json",
    "~/.cursor/mcp.json",
    "~/.config/opencode/opencode.json",
)


def mcp_server_registration(module: str = "rea_mcp") -> dict[str, Any]:
    return {
        "mcpServers": {
            "rea-mcp": {
                "command": sys.executable,
                "args": ["-m", module, "mcp"],
            }
        }
    }


def setup_plan(module: str = "rea_mcp") -> dict[str, Any]:
    return {
        "server": mcp_server_registration(module),
        "known_client_configs": [
            str(Path(location).expanduser()) for location in KNOWN_CLIENT_CONFIGS
        ],
        "note": "Add the server block to your client's MCP configuration and restart the client.",
    }


def write_registration(
    path: str, module: str = "rea_mcp", *, overwrite: bool = False
) -> Result[dict[str, Any], AnalysisError]:
    destination = Path(path).expanduser()
    if destination.exists() and not overwrite:
        return err(
            AnalysisInputError(
                operation="setup", message=f"Destination already exists: {path} (pass --overwrite)"
            )
        )
    backup: str | None = None
    if destination.exists():
        backup_path = destination.with_suffix(destination.suffix + ".bak")
        shutil.copy2(destination, backup_path)
        backup = str(backup_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(mcp_server_registration(module), indent=2), encoding="utf-8")
    return ok({"written": str(destination), "backup": backup})


def write_all_registrations(
    base: str, module: str = "rea_mcp", *, overwrite: bool = False
) -> Result[dict[str, Any], AnalysisError]:
    """Write the registration into every known client config under ``base``.

    ``base`` is a sandbox root joined with each known config's relative path, so
    this never touches a caller's real client configuration.
    """

    root = Path(base).expanduser()
    written: list[str] = []
    skipped: list[str] = []
    for location in KNOWN_CLIENT_CONFIGS:
        relative = Path(location).expanduser().as_posix().lstrip("/")
        destination = root / relative
        result = write_registration(str(destination), module, overwrite=overwrite)
        if result.ok:
            written.append(result.value["written"])
        else:
            skipped.append(str(destination))
    return ok({"base": str(root), "written": written, "skipped": skipped})


def skill_markdown() -> str:
    """Return the bundled agent skill text."""

    from importlib.resources import files

    return (files("rea_mcp") / "data" / "skill.md").read_text(encoding="utf-8")


def install_skill(directory: str) -> Result[dict[str, Any], AnalysisError]:
    """Copy the bundled agent skill into ``<directory>/reverse-engineer-anything/SKILL.md``."""

    destination = Path(directory).expanduser() / "reverse-engineer-anything" / "SKILL.md"
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(skill_markdown(), encoding="utf-8")
    except OSError as cause:
        return err(AnalysisInputError(operation="setup", message=str(cause)))
    return ok({"installed": str(destination)})


__all__ = [
    "KNOWN_CLIENT_CONFIGS",
    "install_skill",
    "mcp_server_registration",
    "setup_plan",
    "skill_markdown",
    "write_all_registrations",
    "write_registration",
]
