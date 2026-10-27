"""Agent/client setup plan and MCP server registration.

Setup is additive and idempotent: it plans changes, and a write only happens when
the caller supplies a destination. Existing files are backed up before rewrite.
"""

from __future__ import annotations

import json
import re
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


def _strip_jsonc(text: str) -> str:
    """Remove comments and trailing commas while preserving string contents."""

    out: list[str] = []
    index = 0
    in_string = False
    escaped = False
    length = len(text)
    while index < length:
        char = text[index]
        if in_string:
            out.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            out.append(char)
            index += 1
            continue
        if char == "/" and index + 1 < length:
            if text[index + 1] == "/":
                index += 2
                while index < length and text[index] not in "\r\n":
                    index += 1
                continue
            if text[index + 1] == "*":
                index += 2
                while index + 1 < length and not (text[index] == "*" and text[index + 1] == "/"):
                    index += 1
                index += 2
                continue
        out.append(char)
        index += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def _skip_ws_comments(text: str, index: int) -> int:
    length = len(text)
    while index < length:
        if text[index] in " \t\r\n":
            index += 1
        elif text[index] == "/" and index + 1 < length and text[index + 1] == "/":
            index += 2
            while index < length and text[index] not in "\r\n":
                index += 1
        elif text[index] == "/" and index + 1 < length and text[index + 1] == "*":
            index += 2
            while index + 1 < length and not (text[index] == "*" and text[index + 1] == "/"):
                index += 1
            index += 2
        else:
            break
    return index


def _string_end(text: str, index: int) -> int:
    index += 1
    while index < len(text):
        if text[index] == "\\":
            index += 2
        elif text[index] == '"':
            return index + 1
        else:
            index += 1
    return len(text)


def _value_end(text: str, index: int) -> int:
    index = _skip_ws_comments(text, index)
    if index >= len(text):
        return index
    char = text[index]
    if char == '"':
        return _string_end(text, index)
    if char in "{[":
        depth = 0
        while index < len(text):
            char = text[index]
            if char == '"':
                index = _string_end(text, index)
                continue
            if char == "/" and index + 1 < len(text) and text[index + 1] in "/*":
                index = _skip_ws_comments(text, index)
                continue
            if char in "{[":
                depth += 1
            elif char in "}]":
                depth -= 1
                if depth == 0:
                    return index + 1
            index += 1
        return len(text)
    while index < len(text) and text[index] not in ",}]":
        index += 1
    return index


def _last_member_span(text: str, key: str) -> tuple[int, int] | None:
    index = _skip_ws_comments(text, 0)
    if index >= len(text) or text[index] != "{":
        return None
    index += 1
    last: tuple[int, int] | None = None
    while index < len(text):
        index = _skip_ws_comments(text, index)
        if index >= len(text) or text[index] == "}":
            break
        if text[index] != '"':
            break
        key_end = _string_end(text, index)
        try:
            name = json.loads(text[index:key_end])
        except ValueError:
            break
        index = _skip_ws_comments(text, key_end)
        if index >= len(text) or text[index] != ":":
            break
        value_start = _skip_ws_comments(text, index + 1)
        value_end = _value_end(text, value_start)
        if name == key:
            last = (value_start, value_end)
        index = _skip_ws_comments(text, value_end)
        if index < len(text) and text[index] == ",":
            index += 1
            continue
        break
    return last


def client_for_path(path: str | Path) -> str:
    lowered = str(path).lower()
    if "opencode" in lowered:
        return "opencode"
    if "cursor" in lowered:
        return "cursor"
    return "generic"


def mcp_server_registration(
    module: str = "rea_mcp", *, toolset: str = "core", client: str = "generic"
) -> dict[str, Any]:
    env = {"REA_MCP_CLIENT": client, "REA_MCP_TOOLSET": toolset}
    command = [sys.executable, "-m", module, "mcp"]
    if client == "opencode":
        return {
            "mcp": {
                "rea": {
                    "type": "local",
                    "command": command,
                    "enabled": True,
                    "environment": env,
                }
            }
        }
    return {
        "mcpServers": {
            "rea-mcp": {
                "command": sys.executable,
                "args": ["-m", module, "mcp"],
                "env": env,
            }
        }
    }


def registration_entry(
    module: str = "rea_mcp", *, toolset: str = "core", client: str = "generic"
) -> tuple[str, str, dict[str, Any]]:
    registration = mcp_server_registration(module, toolset=toolset, client=client)
    root = "mcp" if client == "opencode" else "mcpServers"
    name = "rea" if client == "opencode" else "rea-mcp"
    return root, name, registration[root][name]


def setup_plan(
    module: str = "rea_mcp", *, toolset: str = "core", client: str = "generic"
) -> dict[str, Any]:
    return {
        "server": mcp_server_registration(module, toolset=toolset, client=client),
        "toolset": toolset,
        "client": client,
        "known_client_configs": [
            str(Path(location).expanduser()) for location in KNOWN_CLIENT_CONFIGS
        ],
        "modes": {
            "skill": "Install the agent skill only; no MCP server is registered.",
            "core": "Register the MCP server with the core toolset.",
            "full": "Register the MCP server with the complete compatibility catalog.",
            "hybrid": "Install the skill and register the core MCP server.",
        },
        "note": "Add the server block to your client's MCP configuration and restart the client.",
    }


def write_registration(
    path: str,
    module: str = "rea_mcp",
    *,
    overwrite: bool = False,
    toolset: str = "core",
    client: str | None = None,
) -> Result[dict[str, Any], AnalysisError]:
    destination = Path(path).expanduser()
    selected_client = client or client_for_path(destination)
    root_key, server_name, registration = registration_entry(
        module, toolset=toolset, client=selected_client
    )
    payload: dict[str, Any]
    backup: str | None = None
    if destination.exists():
        try:
            text = destination.read_text(encoding="utf-8")
            span = _last_member_span(text, root_key)
            if span is not None:
                value_start, value_end = span
                try:
                    value = json.loads(_strip_jsonc(text[value_start:value_end]))
                except ValueError:
                    value = None
                if isinstance(value, dict):
                    value[server_name] = registration
                    updated = text[:value_start] + json.dumps(value, indent=2) + text[value_end:]
                    backup_path = destination.with_suffix(destination.suffix + ".bak")
                    shutil.copy2(destination, backup_path)
                    destination.write_text(updated, encoding="utf-8")
                    return ok(
                        {
                            "written": str(destination),
                            "backup": str(backup_path),
                            "merged": True,
                            "edited_last_duplicate": True,
                            "client": selected_client,
                            "toolset": toolset,
                        }
                    )
            try:
                existing = json.loads(text)
            except ValueError:
                existing = json.loads(_strip_jsonc(text))
        except (OSError, ValueError) as cause:
            if not overwrite:
                return err(
                    AnalysisInputError(
                        operation="setup",
                        message=(
                            f"Cannot merge {path}: existing file is not valid JSON/JSONC ({cause}); "
                            "pass --overwrite to replace it."
                        ),
                    )
                )
            existing = None
        if isinstance(existing, dict):
            servers = existing.get(root_key)
            if not isinstance(servers, dict):
                servers = {}
                existing[root_key] = servers
            servers[server_name] = registration
            payload = existing
        else:
            payload = mcp_server_registration(module, toolset=toolset, client=selected_client)
        backup_path = destination.with_suffix(destination.suffix + ".bak")
        shutil.copy2(destination, backup_path)
        backup = str(backup_path)
    else:
        payload = mcp_server_registration(module, toolset=toolset, client=selected_client)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return ok(
        {
            "written": str(destination),
            "backup": backup,
            "merged": backup is not None,
            "client": selected_client,
            "toolset": toolset,
        }
    )


def write_all_registrations(
    base: str,
    module: str = "rea_mcp",
    *,
    overwrite: bool = False,
    toolset: str = "core",
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
        result = write_registration(str(destination), module, overwrite=overwrite, toolset=toolset)
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
