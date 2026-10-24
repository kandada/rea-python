from __future__ import annotations

import os
from pathlib import Path

import pytest

from rea_mcp.domain.binary_target import parse_binary_target
from rea_mcp.providers.il2cpp_metadata import Il2CppMetadataProvider

ROOT = Path(
    os.environ.get("REA_IL2CPP_FIXTURE", "/Volumes/lenovops9/pyrea_local/vendor/fixtures/il2cpp")
)
METADATA = ROOT / "assets/bin/Data/Managed/Metadata/global-metadata.dat"
BINARY = ROOT / "lib/arm64-v8a/libil2cpp.so"
DUMPER = Path(
    os.environ.get(
        "REA_IL2CPP_DUMPER", "/Volumes/lenovops9/pyrea_local/vendor/tools/Il2CppDumper-Python"
    )
)
pytestmark = [
    pytest.mark.real_engine,
    pytest.mark.skipif(
        not METADATA.is_file() or not BINARY.is_file() or not DUMPER.is_dir(),
        reason="requires the downloaded Unity IL2CPP fixture and Il2CppDumper-Python",
    ),
]


def test_real_il2cpp_metadata_and_method_linking(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REA_IL2CPP_DUMPER", str(DUMPER))
    parsed = parse_binary_target(str(METADATA))
    assert parsed.ok
    result = Il2CppMetadataProvider().analyze(
        "inspect_il2cpp_metadata",
        parsed.value,
        {"binary_path": str(BINARY)},
        None,
    )
    assert result.ok
    data = result.value.result
    assert data["metadata_version"] == 27
    assert data["counts"]["types"] > 1000
    assert data["counts"]["methods"] > 1000
    linked = data["binary"]
    assert linked["method_addresses_linked"] is True
    assert linked["method_address_count"] > 1000
    assert linked["method_addresses"][0]["rva"].startswith("0x")
