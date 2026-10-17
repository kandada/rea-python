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


__all__ = ["KNOWN_CLIENT_CONFIGS", "mcp_server_registration", "setup_plan", "write_registration"]
