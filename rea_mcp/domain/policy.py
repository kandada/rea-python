"""Tool effects, approval policy and analysis modes."""

from __future__ import annotations

from typing import Any, Literal

Effect = Literal[
    "read",
    "writes_project",
    "writes_outside",
    "executes_process",
    "network",
    "device",
    "publish",
    "system",
]
ActionKind = Literal[
    "web", "commands", "outside_files", "publish", "delete_outside", "system", "other_tools"
]
Approval = Literal["allow", "ask", "refuse"]
ToolAccess = Literal["target_inside", "target_outside", "target_none"]

DEFAULT_APPROVALS: dict[str, Approval] = {
    "web": "allow",
    "commands": "ask",
    "outside_files": "refuse",
    "publish": "ask",
    "delete_outside": "refuse",
    "system": "refuse",
    "other_tools": "ask",
}


def approvals_for(project: Any) -> dict[str, Approval]:
    value = getattr(project, "approvals", None) or {}
    result = dict(DEFAULT_APPROVALS)
    for key, choice in value.items():
        if key in result and choice in ("allow", "ask", "refuse"):
            result[key] = choice
    return result


def approval_for(project: Any, kind: ActionKind) -> Approval:
    return approvals_for(project).get(kind, "ask")


def clean_room_allows(access: ToolAccess) -> bool:
    return access in ("target_none", "target_outside")


__all__ = [
    "DEFAULT_APPROVALS",
    "ActionKind",
    "Approval",
    "Effect",
    "ToolAccess",
    "approval_for",
    "approvals_for",
    "clean_room_allows",
]
