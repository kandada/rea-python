"""Analysis modes and target access levels."""

from __future__ import annotations

from typing import Literal

Mode = Literal["clean_room", "deep"]
ToolAccess = Literal["target_inside", "target_outside", "target_none"]
CLEAN_ROOM_ACCESS: frozenset[ToolAccess] = frozenset({"target_outside", "target_none"})


def allows(mode: Mode, access: ToolAccess) -> bool:
    return mode == "deep" or access in CLEAN_ROOM_ACCESS


__all__ = ["CLEAN_ROOM_ACCESS", "Mode", "ToolAccess", "allows"]
