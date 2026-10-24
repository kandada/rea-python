from __future__ import annotations

import os
from pathlib import Path

import pytest

from rea_mcp.domain.binary_target import parse_binary_target
from rea_mcp.providers.dotnet_decompiler import CSharpDecompilerProvider


def _target(path: Path):  # type: ignore[no-untyped-def]
    parsed = parse_binary_target(str(path))
    assert parsed.ok
    return parsed.value


@pytest.mark.skipif(os.name == "nt", reason="shell fixture")
def test_ilspycmd_decompiles_and_pages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pe_clr_file: Path
) -> None:
    tool = tmp_path / "ilspycmd"
    tool.write_text(
        "#!/bin/sh\nprintf 'namespace Demo {\\n  class C { void M() {} }\\n}\\n'\n",
        encoding="utf-8",
    )
    tool.chmod(0o755)
    monkeypatch.setenv("REA_ILSPY", str(tool))
    provider = CSharpDecompilerProvider()
    assert provider.capabilities()[0].available is True
    result = provider.analyze(
        "decompile_managed_csharp",
        _target(pe_clr_file),
        {"type": "Demo.C", "offset": 1, "limit": 1},
        None,
    )
    assert result.ok
    data = result.value.result
    assert data["language"] == "csharp"
    assert data["type"] == "Demo.C"
    assert data["source"] == "  class C { void M() {} }\n"
    assert data["source_offset"] == 1
    assert data["next_offset"] == 2


def test_ilspycmd_missing_is_a_capability_error(
    monkeypatch: pytest.MonkeyPatch, pe_file: Path
) -> None:
    monkeypatch.setenv("REA_ILSPY", "/definitely/missing/ilspycmd")
    provider = CSharpDecompilerProvider()
    capability = provider.capabilities()[0]
    assert capability.available is False
    result = provider.analyze(
        "decompile_managed_csharp", _target(pe_file), {"type": "Demo.C"}, None
    )
    assert not result.ok
    assert result.error.tag == "AnalysisCapabilityUnavailableError"
