from __future__ import annotations

from pathlib import Path

from rea_mcp.domain.binary_target import parse_binary_target
from rea_mcp.providers.byte_tools import ByteEntropyProvider, NativeBytesProvider


def _target(path: Path):  # type: ignore[no-untyped-def]
    parsed = parse_binary_target(str(path))
    assert parsed.ok
    return parsed.value


def test_address_mapping_and_read_bytes(pe_file: Path) -> None:
    provider = NativeBytesProvider()
    target = _target(pe_file)
    mapped = provider.analyze("address_to_file_offset", target, {"address": "0x140001000"}, None)
    assert mapped.ok
    assert mapped.value.result["file_offset"] == 0x200
    read = provider.analyze("read_bytes", target, {"address": "0x140001000", "length": 4}, None)
    assert read.ok
    assert read.value.result["hex"] == "90909090"
    assert read.value.result["returned_length"] == 4


def test_search_bytes_wildcards(pe_file: Path) -> None:
    result = NativeBytesProvider().analyze(
        "search_bytes",
        _target(pe_file),
        {"pattern": "90 90 ?? 90", "limit": 2},
        None,
    )
    assert result.ok
    assert result.value.result["match_count"] == 2
    assert result.value.result["matches"][0]["file_offset"] == 0x200


def test_byte_entropy(pe_file: Path) -> None:
    result = ByteEntropyProvider().analyze(
        "inspect_byte_entropy",
        _target(pe_file),
        {"block_size": 256},
        None,
    )
    assert result.ok
    data = result.value.result
    assert data["byte_length"] > 0
    assert 0.0 <= data["entropy"] <= 8.0
    assert data["block_count"] >= 1
    assert data["blocks"][0]["length"] == 256
