from __future__ import annotations

import json
import py_compile
import struct
from pathlib import Path

from rea_mcp.domain.binary_target import parse_binary_target
from rea_mcp.providers.model_artifact import ModelArtifactProvider
from rea_mcp.providers.python_pyc import PythonPycProvider


def _target(path: Path):  # type: ignore[no-untyped-def]
    parsed = parse_binary_target(str(path))
    assert parsed.ok
    return parsed.value


def test_python_pyc_header_and_code(tmp_path: Path) -> None:
    source = tmp_path / "mod.py"
    source.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    pyc = tmp_path / "mod.pyc"
    py_compile.compile(str(source), cfile=str(pyc), doraise=True)
    result = PythonPycProvider().analyze("inspect_python_pyc", _target(pyc), {}, None)
    assert result.ok
    data = result.value.result
    assert data["header"]["python_version"]
    assert data["code_objects"][0]["name"] == "<module>"
    assert any(item["name"] == "add" for item in data["code_objects"])


def test_gguf_and_safetensors_headers(tmp_path: Path) -> None:
    key = b"general.name"
    gguf = b"GGUF" + struct.pack("<IQQ", 3, 0, 1)
    gguf += struct.pack("<Q", len(key)) + key + struct.pack("<II", 4, 7)
    gguf_path = tmp_path / "model.gguf"
    gguf_path.write_bytes(gguf)
    gguf_result = ModelArtifactProvider().analyze(
        "inspect_model_artifact", _target(gguf_path), {"hash": "full"}, None
    )
    assert gguf_result.ok
    assert gguf_result.value.result["metadata"]["general.name"] == 7
    assert gguf_result.value.result["sha256"]

    header = {
        "__metadata__": {"format": "pt"},
        "weight": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]},
    }
    raw = json.dumps(header).encode()
    st = struct.pack("<Q", len(raw)) + raw + b"\x00" * 8
    st_path = tmp_path / "model.safetensors"
    st_path.write_bytes(st)
    st_result = ModelArtifactProvider().analyze(
        "inspect_model_artifact", _target(st_path), {}, None
    )
    assert st_result.ok
    assert st_result.value.result["tensor_count"] == 1
    assert st_result.value.result["tensors"][0]["dtype"] == "F32"
