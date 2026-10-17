"""Provider backed by Rizin/radare2 via ``rzpipe`` (caller-supplied, optional).

Covers the classic analysis operations plus the official native-proxy surface
(navigation, comments/names, procedures, native inspection). When ``rzpipe`` or
Rizin is unavailable, every operation reports an actionable capability error.
"""

from __future__ import annotations

from typing import Any

from ..domain.analysis_error import (
    AnalysisCapabilityUnavailableError,
    AnalysisError,
    AnalysisInputError,
)
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .external import optional_import, resolve_tool
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="rizin", name="REA-Python Rizin adapter", version="1")
_CLASSIC = ("analyze", "function", "decompile", "search", "xrefs", "instructions")
_NAVIGATION = (
    "current_address",
    "goto_address",
    "next_address",
    "prev_address",
    "current_document",
    "current_procedure",
    "list_documents",
    "list_segments",
    "list_strings",
    "list_names",
    "list_procedures",
    "list_bookmarks",
    "set_bookmark",
    "unset_bookmark",
    "get_navigation_context",
    "inspect_address_context",
)
_MUTATION = (
    "address_name",
    "comment",
    "inline_comment",
    "set_address_name",
    "set_addresses_names",
    "set_comment",
    "set_inline_comment",
    "annotate_native_function",
)
_PROCEDURE = (
    "procedure_address",
    "procedure_assembly",
    "procedure_callees",
    "procedure_callers",
    "procedure_info",
    "procedure_pseudo_code",
    "procedure_references",
    "resolve_containing_procedure",
    "resolve_native_call_targets",
    "read_function_instructions",
    "search_procedures",
    "search_strings",
    "find_xrefs_to_name",
)
_NATIVE = (
    "inspect_native_data_type",
    "inspect_native_instruction",
    "inspect_native_load_image",
    "inspect_native_api",
    "analyze_swift_types",
    "get_objc_classes",
    "get_objc_protocols",
)
_OPERATIONS = _CLASSIC + _NAVIGATION + _MUTATION + _PROCEDURE + _NATIVE
_TOOL_ENV = "REA_RIZIN"


class RizinProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        available, reason = self._availability()
        effects = CapabilityEffects(launches_process=True)
        return tuple(
            CapabilityDescriptor(
                operation=operation,
                provider=_PROVIDER,
                available=available,
                reason=reason,
                effects=effects,
                limitations=(
                    "Output depth and decompiler availability follow the caller's Rizin build.",
                ),
            )
            for operation in _OPERATIONS
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format in ("elf", "pe", "mach-o", "mach-o-universal", "raw-binary"):
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported", reason="Rizin requires a native binary", code="target_format_unsupported"
        )

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
        available, reason = self._availability()
        if not available:
            return err(
                AnalysisCapabilityUnavailableError(
                    message=reason or "Rizin is unavailable",
                    provider_id=_PROVIDER.id,
                    operation=operation,
                    reason="provider_unavailable",
                    remediation_action="Install rzpipe and Rizin, or set REA_RIZIN to an absolute path.",
                )
            )
        import rzpipe

        pipe = rzpipe.open(target.path)
        try:
            pipe.cmd("aaa")
            result = _dispatch(pipe, operation, parameters, target.path)
        finally:
            pipe.quit()
        return ok(
            AnalysisExecution(
                result=result,
                provider=_PROVIDER,
                limitations=("Analysis is produced by the caller's Rizin build.",),
            )
        )

    def _availability(self) -> tuple[bool, str | None]:
        if optional_import("rzpipe") is None:
            return False, "the optional 'rzpipe' package is not installed"
        resolution = resolve_tool(("rizin",), _TOOL_ENV)
        if not resolution.available:
            return False, resolution.reason
        return True, None


_STATE: dict[str, dict[str, Any]] = {}


def _state(path: str) -> dict[str, Any]:
    return _STATE.setdefault(
        path,
        {"address": None, "history": [], "bookmarks": {}, "documents": [path]},
    )


def _int(value: Any) -> int | None:
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def _address(pipe: Any, parameters: dict[str, Any]) -> Any:
    if parameters.get("address") is not None:
        return parameters.get("address")
    try:
        return int(pipe.cmd("s").strip(), 0)
    except (TypeError, ValueError):
        return "entry0"


def _dispatch(pipe: Any, operation: str, parameters: dict[str, Any], path: str) -> dict[str, Any]:
    state = _state(path)
    limit = int(parameters.get("limit", 200))
    if operation == "analyze":
        info = pipe.cmdj("ij") or {}
        binfo = info.get("bin") or {}
        return {
            "arch": binfo.get("arch"),
            "bits": binfo.get("bits"),
            "os": binfo.get("os"),
            "entry": binfo.get("baddr"),
        }
    if operation == "function":
        selector = str(parameters.get("function", "main"))
        return {
            "functions": _limited(pipe.cmdj("aflj") or [], limit),
            "selector": selector,
        }
    if operation in ("decompile", "procedure_pseudo_code"):
        selector = str(parameters.get("function", "main"))
        return {"pseudocode": pipe.cmd(f"pdc @ {selector}")}
    if operation in ("search", "search_strings", "search_procedures"):
        needle = str(parameters.get("query", ""))
        if operation == "search_strings":
            strings = pipe.cmdj("izzj") or []
            matches = [
                item for item in strings if needle.lower() in str(item.get("string", "")).lower()
            ]
            return {"matches": _limited(matches, limit), "query": needle}
        if operation == "search_procedures":
            functions = pipe.cmdj("aflj") or []
            matches = [
                item for item in functions if needle.lower() in str(item.get("name", "")).lower()
            ]
            return {"matches": _limited(matches, limit), "query": needle}
        return {"matches": _limited(pipe.cmdj(f"/j {needle}") or [], limit)}
    if operation in ("xrefs", "find_xrefs_to_name"):
        selector = str(parameters.get("address", parameters.get("function", "main")))
        return {"xrefs": _limited(pipe.cmdj(f"axtj @ {selector}") or [], limit)}
    if operation in ("instructions", "read_function_instructions"):
        selector = str(parameters.get("address", "entry0"))
        count = int(parameters.get("count", 64))
        return {"instructions": pipe.cmdj(f"pdj {count} @ {selector}") or []}

    # -- navigation ------------------------------------------------------
    if operation == "list_segments":
        return {"segments": _limited(pipe.cmdj("iSj") or [], limit)}
    if operation == "list_strings":
        return {"strings": _limited(pipe.cmdj("izzj") or [], limit)}
    if operation == "list_names":
        return {"names": _limited(pipe.cmdj("fllj") or pipe.cmdj("fj") or [], limit)}
    if operation == "list_procedures":
        return {"procedures": _limited(pipe.cmdj("aflj") or [], limit)}
    if operation == "list_documents":
        return {"documents": state["documents"]}
    if operation == "current_document":
        return {"document": path}
    if operation == "current_address":
        return {"address": state["address"] or _address(pipe, parameters)}
    if operation == "goto_address":
        address = parameters.get("address")
        if address is None:
            return {"error": "goto_address requires address"}
        if state["address"] is not None:
            state["history"].append(state["address"])
        state["address"] = _int(address)
        pipe.cmd(f"s {address}")
        return {"address": state["address"]}
    if operation in ("next_address", "prev_address"):
        if operation == "next_address":
            current = state["address"] or 0
            state["address"] = int(current) + int(parameters.get("delta") or 1)
        else:
            state["address"] = state["history"].pop() if state["history"] else state["address"]
        return {"address": state["address"]}
    if operation == "list_bookmarks":
        return {"bookmarks": [{"name": k, "address": v} for k, v in state["bookmarks"].items()]}
    if operation == "set_bookmark":
        name = str(parameters.get("name") or parameters.get("address") or "bookmark")
        state["bookmarks"][name] = _int(parameters.get("address")) or state["address"]
        return {"bookmarks": state["bookmarks"], "set": name}
    if operation == "unset_bookmark":
        name = str(parameters.get("name") or "")
        state["bookmarks"].pop(name, None)
        return {"bookmarks": state["bookmarks"], "unset": name}
    if operation in ("get_navigation_context", "inspect_address_context"):
        address = _address(pipe, parameters)
        function = pipe.cmdj(f"afij @ {address}") or {}
        instruction = pipe.cmdj(f"aoj @ {address}") or {}
        xrefs = pipe.cmdj(f"axtj @ {address}") or []
        return {
            "address": address,
            "function": function,
            "instruction": instruction,
            "xrefs": _limited(xrefs, limit),
        }
    if operation == "current_procedure":
        address = state["address"] or _address(pipe, parameters)
        return {"procedure": pipe.cmdj(f"afij @ {address}") or {}}

    # -- comments and names ---------------------------------------------
    if operation == "address_name":
        address = _address(pipe, parameters)
        return {"name": pipe.cmd(f"fd @ {address}").strip(), "address": address}
    if operation in ("comment", "inline_comment"):
        address = _address(pipe, parameters)
        return {"comment": pipe.cmd(f"CC @ {address}").strip(), "address": address}
    if operation == "set_address_name":
        address = _address(pipe, parameters)
        name = str(parameters.get("name") or "")
        pipe.cmd(f"afn {name} @ {address}")
        return {"address": address, "name": name}
    if operation == "set_addresses_names":
        assignments = parameters.get("assignments") or []
        applied = []
        for item in assignments:
            if isinstance(item, dict) and item.get("address") and item.get("name"):
                pipe.cmd(f"afn {item['name']} @ {item['address']}")
                applied.append(item)
        return {"applied": applied}
    if operation == "set_comment":
        address = _address(pipe, parameters)
        text = str(parameters.get("comment") or parameters.get("text") or "")
        pipe.cmd(f"CC {text} @ {address}")
        return {"address": address, "comment": text}
    if operation == "set_inline_comment":
        address = _address(pipe, parameters)
        text = str(parameters.get("comment") or parameters.get("text") or "")
        pipe.cmd(f"CC {text} @ {address}")
        return {"address": address, "comment": text}
    if operation == "annotate_native_function":
        address = _address(pipe, parameters)
        rename = parameters.get("name")
        comment = parameters.get("comment")
        if rename:
            pipe.cmd(f"afn {rename} @ {address}")
        if comment is not None:
            pipe.cmd(f"CC {comment} @ {address}")
        return {
            "address": address,
            "name": rename,
            "comment": comment,
            "function": pipe.cmdj(f"afij @ {address}") or {},
        }

    # -- procedures ------------------------------------------------------
    if operation in ("procedure_info", "resolve_containing_procedure"):
        address = _address(pipe, parameters)
        return {"function": pipe.cmdj(f"afij @ {address}") or {}}
    if operation == "procedure_address":
        address = _address(pipe, parameters)
        info = pipe.cmdj(f"afij @ {address}") or {}
        return {"address": info.get("offset") if isinstance(info, dict) else address}
    if operation == "procedure_assembly":
        selector = str(parameters.get("function", "main"))
        return {"instructions": pipe.cmdj(f"pdfj @ {selector}") or []}
    if operation == "procedure_callees":
        selector = str(parameters.get("function", "main"))
        return {"callees": _limited(pipe.cmdj(f"axfj @ {selector}") or [], limit)}
    if operation == "procedure_callers":
        selector = str(parameters.get("function", "main"))
        return {"callers": _limited(pipe.cmdj(f"axtj @ {selector}") or [], limit)}
    if operation == "procedure_references":
        selector = str(parameters.get("function", "main"))
        return {
            "callers": _limited(pipe.cmdj(f"axtj @ {selector}") or [], limit),
            "callees": _limited(pipe.cmdj(f"axfj @ {selector}") or [], limit),
        }
    if operation == "resolve_native_call_targets":
        address = _address(pipe, parameters)
        return {"targets": _limited(pipe.cmdj(f"axfj @ {address}") or [], limit)}

    # -- native inspection ----------------------------------------------
    if operation == "inspect_native_instruction":
        address = _address(pipe, parameters)
        return {"instruction": pipe.cmdj(f"aoj @ {address}") or {}}
    if operation == "inspect_native_load_image":
        return {
            "info": pipe.cmdj("ij") or {},
            "sections": _limited(pipe.cmdj("iSj") or [], limit),
            "imports": _limited(pipe.cmdj("iij") or [], limit),
        }
    if operation == "inspect_native_api":
        return {"imports": _limited(pipe.cmdj("iij") or [], limit)}
    if operation == "inspect_native_data_type":
        return {
            "types": _limited(pipe.cmdj("tj") or [], limit),
            "limitation": "Type recovery depth follows the Rizin build.",
        }
    if operation in ("analyze_swift_types", "get_objc_classes", "get_objc_protocols"):
        return {
            "classes": _limited(pipe.cmdj("icj") or [], limit),
            "limitation": "Objective-C/Swift metadata requires a Mach-O Rizin build.",
        }
    return {}


def _limited(items: list[Any], limit: int) -> list[Any]:
    return items[: max(0, limit)]


__all__ = ["RizinProvider"]
