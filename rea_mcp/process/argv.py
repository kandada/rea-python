"""Portable parsing for caller-supplied command strings."""

from __future__ import annotations

import os
import shlex


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
        return value[1:-1]
    return value


def split_command(value: str) -> list[str]:
    """Split a command line without mangling Windows path separators.

    POSIX ``shlex`` treats backslashes as escapes, so ``C:\\tools\\app.exe``
    becomes ``C:toolsapp.exe``. Windows mode keeps backslashes and then removes
    the quote characters that ``shlex`` retains in non-POSIX mode.
    """

    if not value.strip():
        return []
    if os.name == "nt":
        return [_unquote(part) for part in shlex.split(value, posix=False)]
    return shlex.split(value)


__all__ = ["split_command"]
