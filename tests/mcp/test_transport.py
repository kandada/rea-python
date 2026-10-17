from typing import Any

from mcp import types
from mcp.shared.message import SessionMessage

from rea_mcp.server.transport import TransportInterceptors


def _response(request_id: int, result: Any) -> SessionMessage:
    return SessionMessage(
        types.JSONRPCMessage(
            root=types.JSONRPCResponse(jsonrpc="2.0", id=request_id, result=result)
        )
    )


def _error(request_id: int, data: Any) -> SessionMessage:
    return SessionMessage(
        types.JSONRPCMessage(
            root=types.JSONRPCError(
                jsonrpc="2.0",
                id=request_id,
                error=types.ErrorData(code=-32603, message="boom", data=data),
            )
        )
    )


def _call_request(request_id: int, name: str) -> SessionMessage:
    return SessionMessage(
        types.JSONRPCMessage(
            root=types.JSONRPCRequest(
                jsonrpc="2.0", id=request_id, method="tools/call", params={"name": name}
            )
        )
    )


def test_untrusted_marker_injected_and_budget_allows_small() -> None:
    interceptors = TransportInterceptors(budget_bytes=1_000_000, retain=lambda *_: "ev_x")
    interceptors.observe_incoming(_call_request(1, "inspect_go_binary"))
    out = interceptors.transform_outgoing(_response(1, {"evidence_id": "ev_1", "content": []}))
    result = out.message.root.result  # type: ignore[union-attr]
    assert result["_meta"]["provenance"]["untrusted_content"] is True


def test_exempt_tool_is_not_marked() -> None:
    interceptors = TransportInterceptors(
        budget_bytes=1_000_000, retain=lambda *_: "ev_x", exempt_tools={"providers"}
    )
    interceptors.observe_incoming(_call_request(2, "providers"))
    out = interceptors.transform_outgoing(_response(2, {"providers": []}))
    assert "_meta" not in out.message.root.result  # type: ignore[union-attr]


def test_oversized_response_is_retained() -> None:
    retained: list[tuple[str, dict[str, Any]]] = []

    def retain(operation: str, payload: dict[str, Any]) -> str:
        retained.append((operation, payload))
        return "ev_retained"

    interceptors = TransportInterceptors(budget_bytes=64, retain=retain)
    interceptors.observe_incoming(_call_request(3, "inspect_strings"))
    out = interceptors.transform_outgoing(_response(3, {"blob": "x" * 5000}))
    root = out.message.root
    assert isinstance(root, types.JSONRPCError)
    assert root.error.data["code"] == "RESOURCE_CONSTRAINT"
    assert root.error.data["evidence_reference"]["evidence_id"] == "ev_retained"
    assert interceptors.retained_count == 1
    assert retained[0][0] == "inspect_strings"


def test_oversized_error_is_retained() -> None:
    interceptors = TransportInterceptors(budget_bytes=32, retain=lambda *_: "ev_err")
    out = interceptors.transform_outgoing(_error(4, {"details": "y" * 500}))
    root = out.message.root
    assert isinstance(root, types.JSONRPCError)
    assert root.error.data["resource"] == "error"
    assert root.error.data["evidence_reference"]["evidence_id"] == "ev_err"


def test_cancellation_is_observed() -> None:
    interceptors = TransportInterceptors(budget_bytes=1_000_000, retain=lambda *_: "ev")
    interceptors.observe_incoming(_call_request(9, "inspect_go_binary"))
    cancelled = SessionMessage(
        types.JSONRPCMessage(
            root=types.JSONRPCNotification(
                jsonrpc="2.0",
                method="notifications/cancelled",
                params={"requestId": 9},
            )
        )
    )
    interceptors.observe_incoming(cancelled)
    assert interceptors.cancelled_count == 1
    # A late response for the cancelled request is no longer marked.
    out = interceptors.transform_outgoing(_response(9, {"content": []}))
    assert "_meta" not in out.message.root.result  # type: ignore[union-attr]
