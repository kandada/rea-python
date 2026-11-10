"""Central metadata for tools that are exposed through CLI and MCP.

Handlers still live in the adapters; this registry is the single source for
tool identity, toolset, mode access, side effects and verification status.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, cast

ToolStatus = Literal["verified", "partial", "fixed", "unverified", "new"]
ToolAccess = Literal["target_inside", "target_outside", "target_none"]


@dataclass(frozen=True)
class ToolSpec:
    id: str
    title: str
    toolset: str
    summary: str = ""
    effects: tuple[str, ...] = ("read",)
    access: ToolAccess = "target_inside"
    status: ToolStatus = "new"
    checked_by: str = ""
    cli_name: str | None = None


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        if spec.id in self._tools:
            raise ValueError(f"duplicate tool id: {spec.id}")
        self._tools[spec.id] = spec

    def upsert(self, spec: ToolSpec) -> None:
        existing = self._tools.get(spec.id)
        if existing is None:
            self._tools[spec.id] = spec
        else:
            self._tools[spec.id] = ToolSpec(
                id=spec.id,
                title=spec.title or existing.title,
                toolset=existing.toolset,
                summary=spec.summary or existing.summary,
                effects=existing.effects,
                access=existing.access,
                status=existing.status,
                checked_by=existing.checked_by,
                cli_name=spec.cli_name or existing.cli_name,
            )

    def get(self, tool_id: str) -> ToolSpec | None:
        return self._tools.get(tool_id)

    def all(self) -> list[ToolSpec]:
        return sorted(self._tools.values(), key=lambda tool: tool.id)

    def toolsets(self) -> dict[str, list[str]]:
        rows: dict[str, list[str]] = {}
        for tool in self.all():
            rows.setdefault(tool.toolset, []).append(tool.id)
        return rows

    def clean_room(self) -> set[str]:
        return {tool.id for tool in self.all() if tool.access != "target_inside"}


REGISTRY = ToolRegistry()


def register(spec: ToolSpec) -> None:
    REGISTRY.register(spec)


def sync_mcp_tools(tools: list[Any]) -> None:
    from ..server.toolsets import infer_access, infer_toolset

    for tool in tools:
        name = str(getattr(tool, "name", ""))
        if not name:
            continue
        REGISTRY.upsert(
            ToolSpec(
                id=name,
                title=name,
                toolset=infer_toolset(name),
                summary=str(getattr(tool, "description", "") or ""),
                access=cast("Any", infer_access(name)),
                status="new",
            )
        )


def sync_cli_names(names: list[str]) -> None:
    from ..server.toolsets import infer_access, infer_toolset

    for name in names:
        tool_id = name.replace("-", "_")
        REGISTRY.upsert(
            ToolSpec(
                id=tool_id,
                title=name,
                toolset=infer_toolset(tool_id),
                access=cast("Any", infer_access(tool_id)),
                status="new",
                cli_name=name,
            )
        )


def tools_for(toolset: str) -> list[ToolSpec]:
    return [tool for tool in REGISTRY.all() if tool.toolset == toolset]


_SPECS = [
    ("project_create", "Create a project", "project", "target_none"),
    ("project_list", "List projects", "project", "target_none"),
    ("project_show", "Show a project", "project", "target_none"),
    ("project_answer", "Answer a project question", "project", "target_none"),
    ("project_approve", "Set project approval policy", "project", "target_none"),
    ("project_finish", "Accept current project result", "project", "target_none"),
    ("project_pin", "Pin a project build", "project", "target_none"),
    ("project_pins", "List project pins", "project", "target_none"),
    ("project_duplicate", "Duplicate a project", "project", "target_none"),
    ("craft_run", "Run Study-Build-Check-Refine", "craft", "target_inside"),
    ("craft_study", "Study a target", "craft", "target_outside"),
    ("craft_build", "Run a coding agent", "craft", "target_inside"),
    ("craft_check", "Run project checks", "craft", "target_none"),
    ("craft_ready", "Mark project ready", "craft", "target_none"),
    ("craft_status", "Show project status", "craft", "target_none"),
    ("inspect_java_archive", "Inspect a Java archive", "java", "target_inside"),
    ("inspect_java_class", "Inspect a Java class", "java", "target_inside"),
    ("search_java_classes", "Search Java classes", "java", "target_inside"),
    ("decompile_java_class", "Decompile Java with Vineflower", "java", "target_inside"),
]
for _id, _title, _toolset, _access in _SPECS:
    register(
        ToolSpec(
            id=_id,
            title=_title,
            toolset=_toolset,
            access=_access,  # type: ignore[arg-type]
            status="verified" if _id not in ("decompile_java_class",) else "partial",
            checked_by="tests/application/test_craft_service.py",
        )
    )

__all__ = ["REGISTRY", "ToolRegistry", "ToolSpec", "register", "tools_for"]
