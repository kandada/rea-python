"""Memory-bounded target reading for structural parsers.

Structural parsers only need read access to the target bytes. Mapping the file
avoids loading large binaries fully into Python memory, while empty or
non-mappable files fall back to a plain read.
"""

from __future__ import annotations

import mmap
import os
from collections.abc import Iterator
from contextlib import contextmanager

ParseBuffer = "bytes | mmap.mmap"


@contextmanager
def open_target(path: str) -> Iterator[bytes | mmap.mmap]:
    size = os.path.getsize(path)
    if size == 0:
        yield b""
        return
    with open(path, "rb") as handle:
        try:
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                yield mapped
        except (ValueError, OSError):
            yield handle.read()


__all__ = ["ParseBuffer", "open_target"]
