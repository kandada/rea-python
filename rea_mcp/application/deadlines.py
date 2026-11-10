"""Per-call deadline helpers (REA 6.8 recovery controls)."""

from __future__ import annotations

import os


def timeout_ms(name: str, default: int) -> int:
    raw = os.environ.get(f"REA_{name.upper()}_TIMEOUT_MS")
    if raw:
        try:
            value = int(raw)
            if 1 <= value <= 86_400_000:
                return value
        except ValueError:
            pass
    return default


def timeout_seconds(name: str, default: float) -> float:
    return timeout_ms(name, int(default * 1000)) / 1000.0


__all__ = ["timeout_ms", "timeout_seconds"]
