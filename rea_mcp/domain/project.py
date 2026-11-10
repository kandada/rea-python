"""Persistent project model for the craft workflow."""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Literal, cast

ProjectMode = Literal["clean_room", "deep"]
ProjectStatus = Literal[
    "new", "studying", "building", "checking", "needs_you", "ready", "stopped", "failed"
]
ProjectStep = Literal["study", "build", "check", "done"]
TargetKind = Literal["website", "local", "file", "none"]
Approval = Literal["allow", "ask", "refuse"]

PROJECT_VERSION = 1
PROJECT_NAME_MAX = 80
_SAFE_NAME = re.compile(r"[^a-zA-Z0-9_-]+")


def now_ms() -> int:
    return int(time.time() * 1000)


def project_id() -> str:
    return "prj_" + uuid.uuid4().hex[:20]


def project_slug(value: str) -> str:
    slug = _SAFE_NAME.sub("-", value.strip()).strip("-").lower()
    return (slug or "project")[:40]


def _target(kind: str, value: str, **extra: Any) -> dict[str, Any]:
    target = {"kind": kind}
    if value:
        target["path" if kind != "website" else "url"] = value
    target.update(extra)
    return target


@dataclass
class ProjectUsage:
    turns: int = 0
    tokens: int = 0
    cost_usd: float = 0.0
    seconds: float = 0.0

    def add(self, other: ProjectUsage) -> None:
        self.turns += other.turns
        self.tokens += other.tokens
        self.cost_usd += other.cost_usd
        self.seconds += other.seconds

    def to_dict(self) -> dict[str, Any]:
        return {
            "turns": self.turns,
            "tokens": self.tokens,
            "cost_usd": self.cost_usd,
            "seconds": round(self.seconds, 3),
        }

    @classmethod
    def from_dict(cls, value: Any) -> ProjectUsage:
        if not isinstance(value, dict):
            return cls()
        return cls(
            turns=int(value.get("turns") or 0),
            tokens=int(value.get("tokens") or 0),
            cost_usd=float(value.get("cost_usd") or 0.0),
            seconds=float(value.get("seconds") or 0.0),
        )


@dataclass
class ProjectManifest:
    version: int = PROJECT_VERSION
    project_id: str = field(default_factory=project_id)
    name: str = "project"
    request: str = ""
    target: dict[str, Any] = field(default_factory=lambda: {"kind": "none"})
    mode: ProjectMode = "clean_room"
    status: ProjectStatus = "new"
    step: ProjectStep = "study"
    stack: str = ""
    builder: str = ""
    agent_session: str | None = None
    created_at: int = field(default_factory=now_ms)
    updated_at: int = field(default_factory=now_ms)
    approvals: dict[str, Approval] = field(default_factory=dict)
    allowed_actions: list[str] = field(default_factory=list)
    usage: ProjectUsage = field(default_factory=ProjectUsage)
    checks: list[dict[str, Any]] = field(default_factory=list)
    note: str = ""

    def touch(
        self, *, status: ProjectStatus | None = None, step: ProjectStep | None = None
    ) -> None:
        if status is not None:
            self.status = status
        if step is not None:
            self.step = step
        self.updated_at = now_ms()

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "project_id": self.project_id,
            "name": self.name,
            "request": self.request,
            "target": self.target,
            "mode": self.mode,
            "status": self.status,
            "step": self.step,
            "stack": self.stack,
            "builder": self.builder,
            "agent_session": self.agent_session,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "approvals": self.approvals,
            "allowed_actions": self.allowed_actions,
            "usage": self.usage.to_dict(),
            "checks": self.checks,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, value: Any) -> ProjectManifest:
        if not isinstance(value, dict):
            raise ValueError("project.json is not an object")
        if int(value.get("version") or 0) > PROJECT_VERSION:
            raise ValueError("project was made by a newer rea-python")
        name = str(value.get("name") or "project")
        if len(name) > PROJECT_NAME_MAX:
            raise ValueError("project name is too long")
        target = (
            cast("dict[str, Any]", value.get("target"))
            if isinstance(value.get("target"), dict)
            else {"kind": "none"}
        )
        mode = (
            cast("ProjectMode", value.get("mode"))
            if value.get("mode") in ("clean_room", "deep")
            else "clean_room"
        )
        status = (
            cast("ProjectStatus", value.get("status"))
            if value.get("status")
            in (
                "new",
                "studying",
                "building",
                "checking",
                "needs_you",
                "ready",
                "stopped",
                "failed",
            )
            else "new"
        )
        step = (
            cast("ProjectStep", value.get("step"))
            if value.get("step") in ("study", "build", "check", "done")
            else "study"
        )
        manifest = cls(
            version=int(value.get("version") or PROJECT_VERSION),
            project_id=str(value.get("project_id") or project_id()),
            name=name,
            request=str(value.get("request") or ""),
            target=target,
            mode=mode,
            status=status,
            step=step,
            stack=str(value.get("stack") or ""),
            builder=str(value.get("builder") or ""),
            agent_session=value.get("agent_session")
            if isinstance(value.get("agent_session"), str)
            else None,
            created_at=int(value.get("created_at") or now_ms()),
            updated_at=int(value.get("updated_at") or now_ms()),
            approvals=cast("dict[str, Approval]", value.get("approvals"))
            if isinstance(value.get("approvals"), dict)
            else {},
            allowed_actions=[str(item) for item in value.get("allowed_actions") or []],
            usage=ProjectUsage.from_dict(value.get("usage")),
            checks=[item for item in (value.get("checks") or []) if isinstance(item, dict)],
            note=str(value.get("note") or ""),
        )
        if manifest.mode not in ("clean_room", "deep"):
            manifest.mode = "clean_room"
        return manifest


def new_manifest(
    *,
    name: str,
    request: str,
    target_path: str | None = None,
    mode: ProjectMode = "clean_room",
    stack: str = "",
    builder: str = "",
) -> ProjectManifest:
    target: dict[str, Any]
    if target_path and re.match(r"^https?://", target_path):
        target = _target("website", target_path)
    elif target_path:
        target = _target("local", target_path)
    else:
        target = {"kind": "none"}
    return ProjectManifest(
        name=name or "project",
        request=request,
        target=target,
        mode=mode,
        stack=stack,
        builder=builder,
    )


def target_path(manifest: ProjectManifest) -> str | None:
    target = manifest.target or {}
    value = target.get("url") or target.get("path")
    return str(value) if isinstance(value, str) and value else None


__all__ = [
    "PROJECT_NAME_MAX",
    "PROJECT_VERSION",
    "Approval",
    "ProjectManifest",
    "ProjectMode",
    "ProjectStatus",
    "ProjectStep",
    "ProjectUsage",
    "TargetKind",
    "new_manifest",
    "now_ms",
    "project_id",
    "project_slug",
    "target_path",
]
