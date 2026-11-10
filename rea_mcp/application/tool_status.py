"""User-facing verification status for craft/project surfaces."""

from __future__ import annotations

from typing import Any

from ..tooling.registry import REGISTRY

_STATUS = (
    ("web-visual", "checks", "verified", "local static website fixture"),
    ("build", "checks", "verified", "static site + unit tests"),
    ("runtime-smoke", "checks", "partial", "runtime.json fixture"),
    ("runtime-ui", "checks", "partial", "OS window inspection; permissions required"),
    ("game-self-test", "checks", "partial", "schema only; no live game run"),
    ("game-godot-build", "checks", "verified", "vendor Godot import fixture"),
    ("environment", "checks", "verified", "tests/application/test_craft_service.py"),
    ("asset-generate", "assets", "partial", "external REA_ASSET_COMMAND required"),
    ("plugins/python", "plugins", "verified", "tests/application/test_plugins.py"),
    ("plugins/webassembly", "plugins", "unverified", "external wasm runtime required"),
)


def tool_status() -> dict[str, Any]:
    rows = [
        {
            "id": tool.id,
            "toolset": tool.toolset,
            "status": tool.status,
            "checked_by": tool.checked_by,
            "access": tool.access,
        }
        for tool in REGISTRY.all()
    ]
    rows.extend(
        {
            "id": name,
            "toolset": toolset,
            "status": status,
            "checked_by": checked_by,
            "access": "target_none",
        }
        for name, toolset, status, checked_by in _STATUS
    )
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    return {
        "statuses": counts,
        "tools": rows,
        "note": (
            "verified means exercised by an automated fixture or a live local run; "
            "partial and unverified are stated explicitly."
        ),
    }


__all__ = ["tool_status"]
