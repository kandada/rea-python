"""Caller-supplied debug sessions: GDB, Rizin debug, and Cutter bridges.

Sessions are lightweight host-side records; commands are executed against the
caller's engine. Unavailable engines report actionable capability errors.
"""

from __future__ import annotations

import json
import socket
import subprocess
from collections.abc import Callable
from typing import Any

from ..domain.analysis_error import (
    AnalysisCapabilityUnavailableError,
    AnalysisError,
    AnalysisInputError,
    ProviderAdapterError,
)
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .external import ToolResolution, optional_import, resolve_tool
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="debug-sessions", name="REA-Python debug sessions", version="1")
_GDB_OPERATIONS = (
    "start_gdb_session",
    "gdb_session_status",
    "close_gdb_session",
    "gdb_console",
)
_RIZIN_OPERATIONS = (
    "start_rizin_debug_session",
    "rizin_debug_session_status",
    "close_rizin_debug_session",
    "rizin_debug_command",
    "execute_rizin_command",
)
_CUTTER_OPERATIONS = ("list_cutter_sessions", "cutter_command")
_OPERATIONS = _GDB_OPERATIONS + _RIZIN_OPERATIONS + _CUTTER_OPERATIONS

_GDB_SESSIONS: dict[str, dict[str, Any]] = {}
_RIZIN_SESSIONS: dict[str, dict[str, Any]] = {}
_CUTTER_SESSIONS: dict[str, dict[str, Any]] = {}
_COUNTER = 0


def _next_id(prefix: str) -> str:
    global _COUNTER
    _COUNTER += 1
    return f"{prefix}_{_COUNTER}"


class DebugSessionProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def _gdb(self) -> ToolResolution:
        return resolve_tool(("gdb",), "REA_GDB")

    def _rizin(self) -> ToolResolution:
        resolution = resolve_tool(("rizin",), "REA_RIZIN")
        if not resolution.available:
            return resolution
        if optional_import("rzpipe") is None:
            return ToolResolution(False, None, "the optional 'rzpipe' package is not installed")
        return resolution

    def _cutter(self) -> ToolResolution:
        import os

        from .external import ToolResolution

        path = os.environ.get("REA_CUTTER_BRIDGE")
        if not path:
            return ToolResolution(False, None, "set REA_CUTTER_BRIDGE to the Cutter bridge socket")
        if not os.path.exists(path):
            return ToolResolution(False, None, f"Cutter bridge socket {path} was not found")
        return ToolResolution(True, path, None)

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        gdb = self._gdb()
        rizin = self._rizin()
        cutter = self._cutter()
        descriptors = []
        for operation in _GDB_OPERATIONS:
            descriptors.append(
                CapabilityDescriptor(
                    operation=operation,
                    provider=_PROVIDER,
                    available=gdb.available,
                    reason=gdb.reason,
                    effects=CapabilityEffects(launches_process=gdb.available),
                )
            )
        for operation in _RIZIN_OPERATIONS:
            descriptors.append(
                CapabilityDescriptor(
                    operation=operation,
                    provider=_PROVIDER,
                    available=rizin.available,
                    reason=rizin.reason,
                    effects=CapabilityEffects(launches_process=rizin.available),
                )
            )
        for operation in _CUTTER_OPERATIONS:
            descriptors.append(
                CapabilityDescriptor(
                    operation=operation,
                    provider=_PROVIDER,
                    available=cutter.available,
                    reason=cutter.reason,
                    effects=CapabilityEffects(launches_process=False, may_show_ui=True),
                )
            )
        return tuple(descriptors)

    def _availability_for(self, operation: str) -> tuple[bool, str | None]:
        if operation in _GDB_OPERATIONS:
            resolution = self._gdb()
        elif operation in _RIZIN_OPERATIONS:
            resolution = self._rizin()
        else:
            resolution = self._cutter()
        return resolution.available, resolution.reason

    def supports(self, target: BinaryTarget) -> TargetSupport:
        return TargetSupport("supported")

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del profile
        if operation not in _OPERATIONS:
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        available, reason = self._availability_for(operation)
        if not available:
            return err(
                AnalysisCapabilityUnavailableError(
                    message=reason or "debug engine is unavailable",
                    provider_id=_PROVIDER.id,
                    operation=operation,
                    reason="provider_unavailable",
                    remediation_action="Install/configure the selected engine or bridge.",
                )
            )
        handler: (
            Callable[[BinaryTarget, dict[str, Any]], Result[AnalysisExecution, AnalysisError]]
            | None
        ) = getattr(self, f"_op_{operation}", None)
        if handler is None:
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        return handler(target, parameters)

    # -- GDB ---------------------------------------------------------------

    def _op_start_gdb_session(
        self, target: BinaryTarget, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        resolution = self._gdb()
        assert resolution.path is not None
        session_id = _next_id("gdb")
        _GDB_SESSIONS[session_id] = {
            "target": target.path,
            "binary": resolution.path,
            "args": parameters.get("args") or [],
        }
        return ok(
            AnalysisExecution(
                result={"session_id": session_id, "target": target.path},
                provider=self.identity(),
                limitations=("Commands run in one-shot batch mode per call.",),
            )
        )

    def _op_gdb_session_status(
        self, target: BinaryTarget, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        del target
        session_id = str(parameters.get("session_id") or "")
        entry = _GDB_SESSIONS.get(session_id)
        if entry is None:
            return err(
                AnalysisInputError(operation="gdb_session_status", message="unknown session_id")
            )
        return ok(
            AnalysisExecution(
                result={"session_id": session_id, **entry, "open": True},
                provider=self.identity(),
            )
        )

    def _op_close_gdb_session(
        self, target: BinaryTarget, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        del target
        session_id = str(parameters.get("session_id") or "")
        entry = _GDB_SESSIONS.pop(session_id, None)
        if entry is None:
            return err(
                AnalysisInputError(operation="close_gdb_session", message="unknown session_id")
            )
        return ok(
            AnalysisExecution(
                result={"session_id": session_id, "closed": True}, provider=self.identity()
            )
        )

    def _op_gdb_console(
        self, target: BinaryTarget, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        resolution = self._gdb()
        assert resolution.path is not None
        commands = parameters.get("commands")
        if not commands:
            return err(AnalysisInputError(operation="gdb_console", message="commands are required"))
        if isinstance(commands, str):
            commands = [commands]
        argv = [resolution.path, "-q", "-batch"]
        for command in commands:
            argv.extend(["-ex", str(command)])
        argv.append(target.path)
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=float(parameters.get("timeout") or 120),
            )
        except (OSError, subprocess.TimeoutExpired) as cause:
            return err(ProviderAdapterError(message=f"gdb failed: {cause}"))
        return ok(
            AnalysisExecution(
                result={
                    "stdout": completed.stdout,
                    "stderr": completed.stderr,
                    "exit_code": completed.returncode,
                },
                provider=self.identity(),
                limitations=("One-shot batch GDB; no persistent interactive state.",),
            )
        )

    # -- Rizin debug -------------------------------------------------------

    def _op_start_rizin_debug_session(
        self, target: BinaryTarget, parameters: dict[str, Any]
    ) -> Any:
        del parameters
        session_id = _next_id("rizin")
        _RIZIN_SESSIONS[session_id] = {"target": target.path, "open": True}
        return ok(
            AnalysisExecution(
                result={"session_id": session_id, "target": target.path},
                provider=self.identity(),
            )
        )

    def _op_rizin_debug_session_status(
        self, target: BinaryTarget, parameters: dict[str, Any]
    ) -> Any:
        del target
        session_id = str(parameters.get("session_id") or "")
        entry = _RIZIN_SESSIONS.get(session_id)
        if entry is None:
            return err(
                AnalysisInputError(
                    operation="rizin_debug_session_status", message="unknown session_id"
                )
            )
        return ok(
            AnalysisExecution(result={"session_id": session_id, **entry}, provider=self.identity())
        )

    def _op_close_rizin_debug_session(
        self, target: BinaryTarget, parameters: dict[str, Any]
    ) -> Any:
        del target
        session_id = str(parameters.get("session_id") or "")
        entry = _RIZIN_SESSIONS.pop(session_id, None)
        if entry is None:
            return err(
                AnalysisInputError(
                    operation="close_rizin_debug_session", message="unknown session_id"
                )
            )
        return ok(
            AnalysisExecution(
                result={"session_id": session_id, "closed": True}, provider=self.identity()
            )
        )

    def _op_rizin_debug_command(
        self, target: BinaryTarget, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        command = parameters.get("command")
        if not command:
            return err(
                AnalysisInputError(operation="rizin_debug_command", message="command is required")
            )
        return self._rizin_command(
            target.path, str(command), debug=True, operation="rizin_debug_command"
        )

    def _op_execute_rizin_command(
        self, target: BinaryTarget, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        command = parameters.get("command")
        if not command:
            return err(
                AnalysisInputError(operation="execute_rizin_command", message="command is required")
            )
        return self._rizin_command(
            target.path, str(command), debug=False, operation="execute_rizin_command"
        )

    def _rizin_command(
        self, path: str, command: str, *, debug: bool, operation: str
    ) -> Result[AnalysisExecution, AnalysisError]:
        import rzpipe

        try:
            pipe = rzpipe.open(path, flags=["-d"] if debug else None)
            try:
                output = pipe.cmd(command)
            finally:
                pipe.quit()
        except Exception as cause:
            return err(ProviderAdapterError(message=f"rizin command failed: {cause}"))
        return ok(
            AnalysisExecution(
                result={"command": command, "output": output},
                provider=self.identity(),
                limitations=("Output follows the caller's Rizin build.",),
            )
        )

    # -- Cutter ------------------------------------------------------------

    def _op_list_cutter_sessions(
        self, target: BinaryTarget, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        del target, parameters
        if not _CUTTER_SESSIONS:
            _CUTTER_SESSIONS["default"] = {"socket": self._cutter().path, "open": True}
        return ok(
            AnalysisExecution(result={"sessions": list(_CUTTER_SESSIONS)}, provider=self.identity())
        )

    def _op_cutter_command(
        self, target: BinaryTarget, parameters: dict[str, Any]
    ) -> Result[AnalysisExecution, AnalysisError]:
        del target
        command = parameters.get("command")
        if not command:
            return err(
                AnalysisInputError(operation="cutter_command", message="command is required")
            )
        path = self._cutter().path
        assert path is not None
        payload = (
            json.dumps(
                {"id": 1, "command": str(command), "target": parameters.get("target")}
            ).encode()
            + b"\n"
        )
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(60)
                client.connect(path)
                client.sendall(payload)
                buffer = b""
                while b"\n" not in buffer:
                    chunk = client.recv(65536)
                    if not chunk:
                        break
                    buffer += chunk
        except OSError as cause:
            return err(ProviderAdapterError(message=f"Cutter bridge request failed: {cause}"))
        try:
            decoded = json.loads(buffer.split(b"\n", 1)[0].decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as cause:
            return err(
                ProviderAdapterError(message=f"Cutter bridge returned malformed data: {cause}")
            )
        return ok(
            AnalysisExecution(
                result=decoded if isinstance(decoded, dict) else {"value": decoded},
                provider=self.identity(),
            )
        )


__all__ = ["DebugSessionProvider"]
