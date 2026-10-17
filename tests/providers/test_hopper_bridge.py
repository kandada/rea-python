import contextlib
import json
import os
import socket
import threading
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from rea_mcp.domain.binary_target import parse_binary_target
from rea_mcp.providers.hopper import HopperProvider


def _short_socket() -> str:
    # AF_UNIX paths are length-limited, so avoid pytest's long tmp dirs.
    return os.path.join("/tmp", f"rea_mcp-hop-{os.getpid()}-{uuid.uuid4().hex[:6]}.sock")


def _target(path: Path) -> object:
    result = parse_binary_target(path)
    assert result.ok
    return result.value


def _fake_bridge(socket_path: str, handler: Callable[[dict[str, Any]], dict[str, Any]]) -> None:
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(socket_path)
    server.listen(1)

    def run() -> None:
        connection, _ = server.accept()
        buffer = b""
        while b"\n" not in buffer:
            chunk = connection.recv(65536)
            if not chunk:
                break
            buffer += chunk
        request = json.loads(buffer.split(b"\n", 1)[0])
        connection.sendall(json.dumps(handler(request)).encode("utf-8") + b"\n")
        connection.close()
        server.close()
        with contextlib.suppress(OSError):
            os.remove(socket_path)

    threading.Thread(target=run, daemon=True).start()


def test_hopper_analyze_round_trip(elf_file: Path, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    socket_path = _short_socket()

    def handler(request: dict[str, Any]) -> dict[str, Any]:
        assert request["operation"] == "hopper_analyze"
        return {"id": request["id"], "ok": True, "result": {"name": "app", "procedure_count": 3}}

    _fake_bridge(socket_path, handler)
    monkeypatch.setenv("REA_HOPPER_BRIDGE", socket_path)
    result = HopperProvider().analyze("hopper_analyze", _target(elf_file), {}, None)
    assert result.ok
    assert result.value.result["procedure_count"] == 3


def test_hopper_unavailable_without_bridge(elf_file: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("REA_HOPPER_BRIDGE", raising=False)
    result = HopperProvider().analyze("hopper_analyze", _target(elf_file), {}, None)
    assert not result.ok
    assert result.error.tag == "AnalysisCapabilityUnavailableError"


def test_hopper_missing_socket(elf_file: Path, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("REA_HOPPER_BRIDGE", str(tmp_path / "absent.sock"))
    capability = HopperProvider().capabilities()[0]
    assert capability.available is False
    assert capability.reason


def test_hopper_bridge_error(elf_file: Path, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    socket_path = _short_socket()

    def handler(request: dict[str, Any]) -> dict[str, Any]:
        return {"id": request["id"], "ok": False, "error": {"message": "boom"}}

    _fake_bridge(socket_path, handler)
    monkeypatch.setenv("REA_HOPPER_BRIDGE", socket_path)
    result = HopperProvider().analyze("hopper_analyze", _target(elf_file), {}, None)
    assert not result.ok
    assert result.error.tag == "ProviderAdapterError"
