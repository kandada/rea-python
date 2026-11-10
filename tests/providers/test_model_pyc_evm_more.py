from __future__ import annotations

import json
import py_compile
import struct
from pathlib import Path

from rea_mcp.domain.binary_target import parse_binary_target
from rea_mcp.providers.evm import EvmInterfaceProvider, _decode_carrier
from rea_mcp.providers.model_artifact import ModelArtifactProvider
from rea_mcp.providers.python_pyc import PythonPycProvider, _const


def _target(path: Path):
    result = parse_binary_target(path)
    assert result.ok
    return result.value


def _gguf_string(value: str) -> bytes:
    raw = value.encode()
    return struct.pack("<Q", len(raw)) + raw


def _gguf() -> bytes:
    metadata = []
    for key, kind, value in (
        ("general.architecture", 8, _gguf_string("llama")),
        ("llama.context_length", 4, struct.pack("<I", 4096)),
        ("flag", 7, b"\x01"),
        ("items", 9, struct.pack("<I", 4) + struct.pack("<Q", 2) + struct.pack("<II", 1, 2)),
    ):
        metadata.append(_gguf_string(key) + struct.pack("<I", kind) + value)
    return b"GGUF" + struct.pack("<IQQ", 3, 0, len(metadata)) + b"".join(metadata)


def test_gguf_metadata_and_hash(tmp_path: Path) -> None:
    path = tmp_path / "model.gguf"
    path.write_bytes(_gguf())
    result = ModelArtifactProvider().analyze(
        "inspect_model_artifact", _target(path), {"hash": "full"}, None
    )
    assert result.ok, result
    payload = result.value.result
    assert payload["format"] == "gguf"
    assert payload["metadata"]["general.architecture"] == "llama"
    assert payload["metadata"]["llama.context_length"] == 4096
    assert payload["metadata"]["flag"] is True
    assert payload["metadata"]["items"] == [1, 2]
    assert payload["tensor_count"] == 0
    assert payload["sha256"]


def test_safetensors_metadata(tmp_path: Path) -> None:
    header = json.dumps(
        {
            "__metadata__": {"format": "pt"},
            "weight": {"dtype": "F16", "shape": [2, 2], "data_offsets": [0, 8]},
        }
    ).encode()
    path = tmp_path / "model.safetensors"
    path.write_bytes(struct.pack("<Q", len(header)) + header + b"\x00" * 8)
    result = ModelArtifactProvider().analyze("inspect_model_artifact", _target(path), {}, None)
    assert result.ok
    assert result.value.result["tensor_count"] == 1
    assert result.value.result["metadata"] == {"format": "pt"}


def test_model_artifact_errors(tmp_path: Path) -> None:
    provider = ModelArtifactProvider()
    bad = tmp_path / "bad.gguf"
    bad.write_bytes(b"GGUF")
    assert not provider.analyze("inspect_model_artifact", _target(bad), {}, None).ok
    unknown = tmp_path / "bad.bin"
    unknown.write_bytes(b"what")
    assert not provider.analyze("inspect_model_artifact", _target(unknown), {}, None).ok
    assert not provider.analyze("other", _target(bad), {}, None).ok
    truncated = tmp_path / "truncated.safetensors"
    truncated.write_bytes(struct.pack("<Q", 999) + b"{}")
    assert not provider.analyze("inspect_model_artifact", _target(truncated), {}, None).ok
    assert provider.supports(_target(bad)).status == "supported"


def test_python_pyc_code_objects(tmp_path: Path) -> None:
    source = tmp_path / "sample.py"
    source.write_text(
        "def outer(value):\n"
        "    def inner():\n"
        "        return value\n"
        "    return inner()\n"
        "DATA = b'bytes'\n",
        encoding="utf-8",
    )
    compiled = tmp_path / "sample.pyc"
    py_compile.compile(str(source), cfile=str(compiled), doraise=True)
    result = PythonPycProvider().analyze("inspect_python_pyc", _target(compiled), {}, None)
    assert result.ok, result
    payload = result.value.result
    assert payload["code_count"] >= 2
    assert payload["coverage"]["state"] == "complete"
    names = {item["name"] for item in payload["code_objects"]}
    assert {"outer", "inner"} <= names
    assert any(item["consts"] for item in payload["code_objects"])


def test_python_pyc_errors_and_consts(tmp_path: Path) -> None:
    provider = PythonPycProvider()
    short = tmp_path / "short.pyc"
    short.write_bytes(b"x")
    assert not provider.analyze("inspect_python_pyc", _target(short), {}, None).ok
    bad = tmp_path / "bad.pyc"
    bad.write_bytes(b"\x00" * 16 + b"not marshal")
    result = provider.analyze("inspect_python_pyc", _target(bad), {}, None)
    assert result.ok
    assert result.value.result["coverage"]["state"] == "unavailable"
    assert not provider.analyze("other", _target(bad), {}, None).ok
    assert _const("x" * 600)["length"] == 600
    assert _const(b"abc")["type"] == "bytes"
    assert _const((1, 2)) == {"type": "tuple", "length": 2}
    assert _const(object())["type"] == "object"


def test_evm_carrier_decoding() -> None:
    assert _decode_carrier(b"0x60016000") == ("hex", b"\x60\x01\x60\x00")
    assert _decode_carrier(b"abc") == ("raw", b"abc")
    assert _decode_carrier(b"0xzz") == ("raw", b"0xzz")
    provider = EvmInterfaceProvider()
    assert provider._availability()[0] is False
    assert provider.supports(_target(Path(__file__))).status == "supported"
