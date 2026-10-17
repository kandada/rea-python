"""Pure-Python firmware signature scanner (no external tools)."""

from __future__ import annotations

import mmap
from typing import Any

_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"\x27\x05\x19\x56", "U-Boot uImage header"),
    (b"hsqs", "SquashFS filesystem"),
    (b"sqsh", "SquashFS filesystem (big-endian)"),
    (b"#UBI#", "UBI erase-count header"),
    (b"UBI#", "UBI volume header"),
    (b"UBI!", "UBI image sequence"),
    (b"\x2d\x72\x6f\x6d", "RomFS filesystem"),
    (b"070701", "ASCII cpio archive"),
    (b"070702", "ASCII cpio archive (CRC)"),
    (b"\x45\x3d\xcd\x28", "CramFS filesystem"),
    (b"\x7fELF", "ELF executable"),
    (b"\x1f\x8b\x08", "gzip compressed data"),
    (b"\xfd7zXZ\x00", "XZ compressed data"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"\xd0\x0d\xfe\xed", "Flattened device tree"),
    (b"ANDROID!", "Android boot image"),
    (b"ustar", "POSIX tar archive"),
    (b"\x53\xef", "ext filesystem superblock"),
    (b"\x06\x10\x18\x31", "UBIFS node"),
)


def scan_firmware(data: bytes | mmap.mmap, *, max_regions: int = 256) -> list[dict[str, Any]]:
    """Return signature regions ordered by offset."""

    regions: list[dict[str, Any]] = []
    for magic, description in _SIGNATURES:
        start = 0
        while len(regions) < max_regions:
            index = data.find(magic, start)
            if index < 0:
                break
            if not (len(regions) < max_regions):
                break
            regions.append(
                {
                    "offset": index,
                    "signature": magic.hex(),
                    "description": description,
                }
            )
            start = index + 1
    regions.sort(key=lambda region: region["offset"])
    return regions[:max_regions]


__all__ = ["scan_firmware"]
