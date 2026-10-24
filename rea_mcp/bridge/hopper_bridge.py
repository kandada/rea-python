"""Hopper bridge: run this *inside* Hopper and point REA-Python at the socket.

Usage (Hopper's Python console or ``hopper --script``):

    exec(open("/path/to/bridge/hopper_bridge.py").read())

It starts a Unix-socket JSON-line server and prints the socket path. Point the
environment variable ``REA_HOPPER_BRIDGE`` at that path. REA-Python's Hopper provider
connects to it; REA-Python never starts or controls Hopper itself.

Protocol: one JSON object per line.
  request:  {"id": n, "operation": str, "parameters": {...}}
  response: {"id": n, "ok": true, "result": {...}}
            {"id": n, "ok": false, "error": {"message": str}}
"""

from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
from typing import Any

_DEFAULT_SOCKET = os.path.join(tempfile.gettempdir(), "rea_mcp-hopper-bridge.sock")


def _dispatch(operation: str, parameters: dict[str, Any]) -> dict[str, Any]:
    import hopper  # type: ignore[import-not-found]  # available inside Hopper

    document = hopper.documents.current
    if operation == "hopper_analyze":
        procedures = list(document.getProcedures())
        return {
            "name": document.name,
            "entrypoint": hex(document.entrypoint),
            "procedure_count": len(procedures),
            "arch": str(document.cpu),
        }
    if operation == "hopper_function":
        procedures = [procedure.name for procedure in document.getProcedures()]
        return {"functions": procedures[: int(parameters.get("limit", 500))]}
    if operation == "hopper_decompile":
        name = parameters.get("function")
        for procedure in document.getProcedures():
            if procedure.name == name:
                target = document.getProcedureAtAddress(procedure.address)
                return {"function": name, "pseudocode": getattr(target, "decompilation", None)}
        raise ValueError(f"function {name!r} was not found")
    if operation == "hopper_xrefs":
        address = parameters.get("address")
        address_int = int(address, 16) if isinstance(address, str) else int(address or 0)
        references = document.getReferencesToAddress(address_int)
        return {"address": hex(address_int), "references": [hex(ref.address) for ref in references]}
    raise ValueError(f"unsupported operation {operation}")


def _handle(connection: socket.socket) -> None:
    buffer = b""
    while b"\n" not in buffer:
        chunk = connection.recv(65536)
        if not chunk:
            return
        buffer += chunk
    line = buffer.split(b"\n", 1)[0]
    request = json.loads(line.decode("utf-8"))
    request_id = request.get("id")
    try:
        result = _dispatch(str(request.get("operation", "")), request.get("parameters") or {})
        response = {"id": request_id, "ok": True, "result": result}
    except Exception as cause:
        response = {"id": request_id, "ok": False, "error": {"message": str(cause)}}
    connection.sendall(json.dumps(response).encode("utf-8") + b"\n")


def serve(socket_path: str = _DEFAULT_SOCKET) -> None:
    if os.path.exists(socket_path):
        os.remove(socket_path)
    family = getattr(socket, "AF_UNIX", None)
    if family is None:
        sys.stderr.write("rea_mcp Hopper bridge requires Unix-domain sockets\n")
        return
    server = socket.socket(family, socket.SOCK_STREAM)
    server.bind(socket_path)
    server.listen(4)
    sys.stderr.write(f"rea_mcp Hopper bridge listening at {socket_path}\n")
    while True:
        connection, _ = server.accept()
        try:
            _handle(connection)
        finally:
            connection.close()


def main() -> None:
    serve(
        sys.argv[1] if len(sys.argv) > 1 else os.environ.get("REA_HOPPER_BRIDGE", _DEFAULT_SOCKET)
    )


if __name__ == "__main__":
    main()
