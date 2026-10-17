"""Pure-Python VCD parsing and a UART decoder (sigrok-style captures)."""

from __future__ import annotations

import re
from typing import Any

_TIMESCALE_RE = re.compile(r"^\$timescale\s+(\d+)\s*(\w+)\s+\$end")
_VAR_RE = re.compile(r"^\$var\s+wire\s+\d+\s+(\S+)\s+(\S+)\s+\$end")
_SCALE_SECONDS = {
    "s": 1.0,
    "ms": 1e-3,
    "us": 1e-6,
    "ns": 1e-9,
    "ps": 1e-12,
}


def parse_vcd(text: str) -> dict[str, Any]:
    """Parse a Value Change Dump into ``{timescale_seconds, signals}``."""

    timescale_seconds = 1e-6
    symbols: dict[str, str] = {}
    changes: dict[str, list[tuple[int, str]]] = {}
    current_time = 0
    in_definitions = True
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("$timescale"):
            match = _TIMESCALE_RE.match(line)
            if match:
                magnitude = int(match.group(1))
                timescale_seconds = magnitude * _SCALE_SECONDS.get(match.group(2), 1e-6)
            continue
        if line.startswith("$var"):
            match = _VAR_RE.match(line)
            if match:
                symbol, name = match.group(1), match.group(2)
                symbols[symbol] = name
                changes.setdefault(name, [])
            continue
        if line.startswith("$enddefinitions"):
            in_definitions = False
            continue
        if in_definitions:
            continue
        if line.startswith("#"):
            current_time = int(line[1:])
            continue
        if line[0] in "01xz":
            changes[symbols.get(line[1:], line[1:])].append((current_time, line[0]))
    return {"timescale_seconds": timescale_seconds, "signals": changes}


def decode_uart(
    transitions: list[tuple[int, str]], *, timescale_seconds: float, baud: int, bits: int = 8
) -> dict[str, Any]:
    """Decode 8N1 UART from a list of ``(tick, level)`` transitions."""

    bit_ticks = (1.0 / baud) / timescale_seconds
    levels = [(tick, "1" if level in "1x" else "0") for tick, level in transitions]
    by_tick = dict(levels)
    max_tick = transitions[-1][0] if transitions else 0
    decoded: list[int] = []
    index = 0
    while index < len(levels) - 1:
        _tick, level = levels[index]
        next_tick, next_level = levels[index + 1]
        if level == "1" and next_level == "0":  # falling edge = start bit
            start = next_tick
            sample_center = start + 1.5 * bit_ticks
            value = 0
            ok = True
            for bit in range(bits):
                sample_tick = round(sample_center + bit * bit_ticks)
                if sample_tick > max_tick:
                    ok = False
                    break
                if _level_at(levels, sample_tick) == "1":
                    value |= 1 << bit
            stop_sample = round(sample_center + bits * bit_ticks)
            if ok and _level_at(levels, stop_sample) == "1":
                decoded.append(value)
                next_start = start + (bits + 1) * bit_ticks
                while index < len(levels) and levels[index][0] < next_start:
                    index += 1
                continue
        index += 1
    del by_tick
    return {
        "baud": baud,
        "byte_count": len(decoded),
        "bytes": decoded,
        "ascii": "".join(chr(value) if 32 <= value < 127 else "." for value in decoded),
    }


def _level_at(levels: list[tuple[int, str]], tick: int) -> str:
    level = "1"
    for change_tick, value in levels:
        if change_tick <= tick:
            level = value
        else:
            break
    return level


__all__ = ["decode_uart", "parse_vcd"]
