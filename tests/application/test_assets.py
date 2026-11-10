from __future__ import annotations

import sys
from pathlib import Path

from rea_mcp.application.assets import generate_asset


def test_external_asset_generator(tmp_path: Path, monkeypatch) -> None:
    script = tmp_path / "asset.py"
    script.write_text(
        "import pathlib, sys\npathlib.Path(sys.argv[2]).write_bytes(b'PNG')\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("REA_ASSET_COMMAND", f"{sys.executable} {script} {{prompt}} {{output}}")
    output = tmp_path / "out.png"
    result = generate_asset("a blue square", str(output))
    assert result.ok
    assert output.read_bytes() == b"PNG"
