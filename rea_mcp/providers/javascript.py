"""JavaScript/Electron static application graph provider.

Builds a module graph from an extracted app directory or an ASAR archive by
extracting ``require``/``import`` edges. Electron boundaries (main/preload/
renderer, ipcMain/ipcRenderer) are detected by filename and token presence. A
bounded, regex-based extractor is used; this is structural, not a full parser.
"""

from __future__ import annotations

import json
import posixpath
import re
import struct
from pathlib import Path
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .paging import page_sequence
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(
    id="javascript", name="REA-Python JavaScript application graph", version="1"
)

_IMPORT_RE = re.compile(
    r"""(?:require\s*\(\s*|from\s+|import\s*\(\s*)["']([^"']+)["']""",
)
_JS_SUFFIXES = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")
_MAX_FILES = 500
_MAX_FILE_BYTES = 512 * 1024


class JavaScriptApplicationProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="analyze_javascript_application",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=(
                    "Edges come from a bounded regex extractor; dynamic requires may be missed.",
                ),
            ),
            CapabilityDescriptor(
                operation="inspect_javascript_webmcp",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=(
                    "Static WebMCP declaration discovery only; runtime registration is not observed.",
                ),
            ),
            CapabilityDescriptor(
                operation="inspect_javascript_source_maps",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=(
                    "Static source-map inventory only; mappings are not resolved to original positions.",
                ),
            ),
            CapabilityDescriptor(
                operation="inspect_javascript_dataflow",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=(
                    "Storage and DOM flows are regex/line based; dynamic property access and interprocedural flows may be missed.",
                ),
            ),
            CapabilityDescriptor(
                operation="inspect_javascript_routes",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=(
                    "Routes are static regex candidates; dynamic routes and runtime URL construction may be missed.",
                ),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format in ("asar", "directory") or target.kind == "directory":
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported", reason="not a JS app directory or ASAR", code="target_format_unsupported"
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del profile
        if operation not in (
            "analyze_javascript_application",
            "inspect_javascript_routes",
            "inspect_javascript_source_maps",
            "inspect_javascript_webmcp",
            "inspect_javascript_dataflow",
        ):
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        path = Path(target.path)
        asar_integrity: dict[str, Any] | None = None
        try:
            if target.format == "asar" or path.suffix == ".asar":
                sources, asar_integrity = _read_asar_sources(path)
            else:
                sources = _read_directory_sources(path)
        except OSError as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))

        if operation == "inspect_javascript_webmcp":
            return ok(
                AnalysisExecution(
                    result=_webmcp(sources, parameters),
                    provider=self.identity(),
                    limitations=(
                        "Static WebMCP declarations only; runtime registration and schemas may be dynamic.",
                    ),
                )
            )

        if operation == "inspect_javascript_dataflow":
            return ok(
                AnalysisExecution(
                    result=_dataflow(sources, parameters),
                    provider=self.identity(),
                    limitations=(
                        "Static storage/DOM flows only; dynamic property access, aliasing and interprocedural calls may be missed.",
                    ),
                )
            )

        if operation == "inspect_javascript_source_maps":
            return ok(
                AnalysisExecution(
                    result=_source_maps(path, sources, parameters),
                    provider=self.identity(),
                    limitations=(
                        "Source maps are inventoried, not decoded into original source positions.",
                    ),
                )
            )

        if operation == "inspect_javascript_routes":
            return ok(
                AnalysisExecution(
                    result=_routes(sources, parameters),
                    provider=self.identity(),
                    limitations=(
                        "Routes are static regex candidates; dynamic routes and runtime URL construction may be missed.",
                    ),
                )
            )

        modules: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, str]] = []
        electron_flags: set[str] = set()
        for name, text in sources.items():
            imports = sorted(set(_IMPORT_RE.findall(text)))
            modules[name] = {"imports": imports, "size": len(text)}
            for spec in imports:
                edges.append({"from": name, "to": spec})
            lowered = name.lower()
            if "preload" in lowered:
                electron_flags.add("preload")
            elif "main" in lowered:
                electron_flags.add("main")
            elif "renderer" in lowered:
                electron_flags.add("renderer")
            if "ipcMain" in text:
                electron_flags.add("ipcMain")
            if "ipcRenderer" in text:
                electron_flags.add("ipcRenderer")

        module_page = page_sequence(
            sorted(modules.items()),
            offset=int(parameters.get("module_offset") or 0),
            limit=int(parameters.get("module_limit") or 500),
        )
        edge_page = page_sequence(
            edges,
            offset=int(parameters.get("edge_offset") or 0),
            limit=int(parameters.get("edge_limit") or 500),
        )
        result: dict[str, Any] = {
            "module_count": len(modules),
            "module_offset": module_page["offset"],
            "next_module_offset": module_page["next_offset"],
            "modules": dict(module_page["items"]),
            "edge_count": len(edges),
            "edge_offset": edge_page["offset"],
            "next_edge_offset": edge_page["next_offset"],
            "edges": edge_page["items"],
            "electron": {
                "is_electron": bool(
                    {"main", "preload", "renderer", "ipcMain", "ipcRenderer"} & electron_flags
                ),
                "roles": sorted(electron_flags),
            },
        }
        if asar_integrity is not None:
            result["asar_integrity"] = asar_integrity
        return ok(
            AnalysisExecution(
                result=result,
                provider=_PROVIDER,
                limitations=("Graph edges are specifier strings, not resolved module identities.",),
            )
        )


def _read_directory_sources(root: Path) -> dict[str, str]:
    sources: dict[str, str] = {}
    for child in sorted(root.rglob("*")):
        if not child.is_file() or child.suffix.lower() not in _JS_SUFFIXES:
            continue
        if "node_modules" in child.parts:
            continue
        if len(sources) >= _MAX_FILES:
            break
        sources[child.relative_to(root).as_posix()] = _read_text(child)
    return sources


def _read_asar_sources(path: Path) -> tuple[dict[str, str], dict[str, Any]]:
    with open(path, "rb") as handle:
        prefix = handle.read(16)
        if len(prefix) < 16:
            raise OSError("ASAR header is truncated")
        header_size = struct.unpack_from("<I", prefix, 4)[0]
        json_size = struct.unpack_from("<I", prefix, 8)[0]
        handle.seek(12)
        raw = handle.read(json_size)
        parsed = json.loads(raw.decode("utf-8"))
        data_start = 8 + header_size
        entries: list[tuple[str, int, int]] = []
        _collect_asar_files(parsed.get("files", {}), "", entries)
        sources: dict[str, str] = {}
        for rel, offset, size in entries[:_MAX_FILES]:
            handle.seek(data_start + offset)
            sources[rel] = handle.read(min(size, _MAX_FILE_BYTES)).decode("utf-8", errors="replace")
        integrity_entries: list[dict[str, Any]] = []
        _collect_asar_integrity(parsed.get("files", {}), "", integrity_entries)
    summary = {
        "entry_count": len(integrity_entries),
        "algorithms": sorted(
            {str(item["algorithm"]) for item in integrity_entries if item.get("algorithm")}
        ),
        "entries": integrity_entries[:200],
    }
    return sources, summary


def _collect_asar_integrity(node: Any, prefix: str, out: list[dict[str, Any]]) -> None:
    if not isinstance(node, dict):
        return
    for name, child in node.items():
        if not isinstance(child, dict):
            continue
        rel = f"{prefix}/{name}" if prefix else name
        if isinstance(child.get("files"), dict):
            _collect_asar_integrity(child["files"], rel, out)
            continue
        integrity = child.get("integrity")
        if isinstance(integrity, dict):
            out.append(
                {
                    "path": rel,
                    "algorithm": integrity.get("algorithm"),
                    "hash": integrity.get("hash"),
                    "block_size": integrity.get("blockSize"),
                    "block_count": len(integrity.get("blocks") or []),
                }
            )


def _collect_asar_files(node: Any, prefix: str, out: list[tuple[str, int, int]]) -> None:
    if not isinstance(node, dict):
        return
    for name, child in node.items():
        rel = f"{prefix}/{name}" if prefix else name
        if isinstance(child, dict) and "files" in child:
            _collect_asar_files(child["files"], rel, out)
        elif isinstance(child, dict) and rel.endswith(_JS_SUFFIXES) and "offset" in child:
            out.append((rel, int(child.get("offset", 0)), int(child.get("size", 0))))


def _read_text(path: Path) -> str:
    try:
        data = path.read_bytes()[:_MAX_FILE_BYTES]
    except OSError:
        return ""
    return data.decode("utf-8", errors="replace")


_SOURCE_MAP_RE = re.compile(r"(?://[#@]\s*sourceMappingURL=|/\*[#@]\s*sourceMappingURL=)([^\s*]+)")
_ROUTE_PATTERNS = (
    (
        "route",
        re.compile(r"""\b(?:get|post|put|patch|delete|options|head)\s*\(\s*["'`](/[^"'`]+)["'`]"""),
    ),
    ("route", re.compile(r"""\b(?:route|use)\s*\(\s*["'`](/[^"'`]+)["'`]""")),
    ("fetch", re.compile(r"""\bfetch\s*\(\s*["'`]((?:https?://|/)[^"'`]+)["'`]""")),
    ("path", re.compile(r"""\bpath\s*:\s*["'`](/[^"'`]+)["'`]""")),
)


def _webmcp(sources: dict[str, str], parameters: dict[str, Any]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for module, text in sorted(sources.items()):
        for pattern, kind in (
            (r"navigator\.modelContext", "model-context"),
            (r"\.registerTool\s*\(", "register-tool"),
            (r"\.defineTool\s*\(", "define-tool"),
            (r"inputSchema\s*:", "input-schema"),
        ):
            for match in re.finditer(pattern, text):
                line = text.count("\n", 0, match.start()) + 1
                name_match = re.search(
                    r"(?:name|title)\s*:\s*[\"']([^\"']+)[\"']",
                    text[match.start() : match.start() + 400],
                )
                rows.append(
                    {
                        "module": module,
                        "line": line,
                        "kind": kind,
                        "name": name_match.group(1) if name_match else None,
                    }
                )
    page = page_sequence(
        rows,
        offset=int(parameters.get("offset") or 0),
        limit=int(parameters.get("limit") or 200),
    )
    return {
        "candidate_count": len(rows),
        "offset": page["offset"],
        "next_offset": page["next_offset"],
        "candidates": page["items"],
        "limitations": (
            "Static source matching only; dynamic WebMCP tool registration is not executed.",
        ),
    }


def _source_maps(root: Path, sources: dict[str, str], parameters: dict[str, Any]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for module, text in sorted(sources.items()):
        match = _SOURCE_MAP_RE.search(text)
        if match is None:
            continue
        reference = match.group(1)
        row: dict[str, Any] = {
            "module": module,
            "source_mapping_url": reference,
            "map_path": None,
            "source_count": None,
            "name_count": None,
            "has_sources_content": None,
            "source_root": None,
            "decode_error": None,
        }
        if reference.startswith(("http://", "https://", "data:")):
            row["decode_error"] = "remote or inline source maps are not fetched"
            rows.append(row)
            continue
        map_path = (root / reference.split("?", 1)[0]).resolve()
        try:
            map_path.relative_to(root.resolve())
        except ValueError:
            row["decode_error"] = "source map path escapes the application root"
            rows.append(row)
            continue
        row["map_path"] = map_path.relative_to(root.resolve()).as_posix()
        try:
            payload = json.loads(map_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as cause:
            row["decode_error"] = str(cause)
            rows.append(row)
            continue
        if not isinstance(payload, dict):
            row["decode_error"] = "source map is not an object"
            rows.append(row)
            continue
        sources_list = payload.get("sources") or []
        names_list = payload.get("names") or []
        row["source_count"] = len(sources_list)
        row["name_count"] = len(names_list)
        row["source_root"] = payload.get("sourceRoot")
        row["has_sources_content"] = bool(payload.get("sourcesContent"))
        decoded = _decode_mappings(payload.get("mappings"))
        row["mapping_count"] = decoded["mapping_count"]
        row["generated_line_count"] = decoded["generated_line_count"]
        if parameters.get("line") is not None:
            line = max(1, int(parameters.get("line") or 1)) - 1
            column = max(0, int(parameters.get("column") or 0))
            original = _lookup_mapping(decoded["lines"], line, column)
            row["lookup"] = (
                None
                if original is None
                else {
                    "generated_line": line + 1,
                    "generated_column": column,
                    "source": sources_list[original["source"]]
                    if 0 <= original["source"] < len(sources_list)
                    else None,
                    "original_line": original["original_line"] + 1,
                    "original_column": original["original_column"],
                    "name": names_list[original["name"]]
                    if original.get("name") is not None and 0 <= original["name"] < len(names_list)
                    else None,
                }
            )
        rows.append(row)
    page = page_sequence(
        rows,
        offset=int(parameters.get("offset") or 0),
        limit=int(parameters.get("limit") or 200),
    )
    return {
        "source_map_count": len(rows),
        "offset": page["offset"],
        "next_offset": page["next_offset"],
        "source_maps": page["items"],
        "truncated": len(rows) >= 1000,
    }


_STORAGE_PATTERNS = (
    (
        "storage-get",
        re.compile(r"\b(?:localStorage|sessionStorage)\.getItem\s*\(\s*['\"`]([^'\"`]+)"),
    ),
    (
        "storage-set",
        re.compile(r"\b(?:localStorage|sessionStorage)\.setItem\s*\(\s*['\"`]([^'\"`]+)"),
    ),
    (
        "storage-remove",
        re.compile(r"\b(?:localStorage|sessionStorage)\.removeItem\s*\(\s*['\"`]([^'\"`]+)"),
    ),
    ("storage-clear", re.compile(r"\b(?:localStorage|sessionStorage)\.clear\s*\(")),
    ("cookie-read", re.compile(r"\bdocument\.cookie\b(?!\s*=)")),
    ("cookie-write", re.compile(r"\bdocument\.cookie\s*=")),
    ("indexeddb", re.compile(r"\bindexedDB\.(open|deleteDatabase)\s*\(\s*['\"`]([^'\"`]+)")),
    ("idb-store", re.compile(r"\bobjectStore\s*\(\s*['\"`]([^'\"`]+)")),
    ("idb-write", re.compile(r"\.(?:put|add|delete)\s*\(")),
    ("cache", re.compile(r"\bcaches\.(?:open|delete|match|has)\s*\(\s*['\"`]([^'\"`]+)")),
)
_SOURCE_PATTERNS = (
    ("location", re.compile(r"\b(?:location\.(?:href|search|hash)|window\.location)\b")),
    ("cookie", re.compile(r"\bdocument\.cookie\b(?!\s*=)")),
    ("storage-get", re.compile(r"\b(?:localStorage|sessionStorage)\.getItem\s*\(")),
    ("message", re.compile(r"\b(?:event|evt|e|message)\.data\b")),
    ("websocket-message", re.compile(r"\.onmessage\s*=|\baddEventListener\s*\(\s*['\"]message")),
    ("dom-value", re.compile(r"\.(?:value|textContent)\b")),
    ("document-url", re.compile(r"\bdocument\.(?:URL|referrer|documentURI)\b")),
    ("window-name", re.compile(r"\bwindow\.name\b")),
    ("url-params", re.compile(r"\bnew\s+URLSearchParams\b")),
)
_SINK_PATTERNS = (
    ("network", re.compile(r"\b(?:fetch|axios(?:\.\w+)?|sendBeacon)\s*\(")),
    ("xhr", re.compile(r"\bXMLHttpRequest\b|\.open\s*\(\s*['\"](?:GET|POST|PUT|PATCH|DELETE)")),
    ("websocket", re.compile(r"\bnew\s+WebSocket\s*\(|\b(?:socket|ws|websocket)\.send\s*\(")),
    ("storage-set", re.compile(r"\b(?:localStorage|sessionStorage)\.setItem\s*\(")),
    ("cookie-write", re.compile(r"\bdocument\.cookie\s*=")),
    ("indexeddb", re.compile(r"\bindexedDB\.|\.objectStore\s*\(")),
    ("dom-html", re.compile(r"\.(?:innerHTML|outerHTML)\s*=|document\.write\s*\(")),
    ("eval", re.compile(r"\b(?:eval|Function)\s*\(")),
    ("postmessage", re.compile(r"\.postMessage\s*\(")),
    (
        "navigation",
        re.compile(r"\b(?:location\.(?:assign|replace)|window\.open|window\.location)\s*[=(]"),
    ),
)
_ASSIGN_RE = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=")


_IMPORT_NAMED_RE = re.compile(r"""import\s*\{([^}]+)\}\s*from\s*["']([^"']+)["']""")
_IMPORT_DEFAULT_RE = re.compile(
    r"""import\s+([A-Za-z_$][\w$]*)\s*(?:,\s*\{[^}]*\})?\s*from\s*["']([^"']+)["']"""
)
_REQUIRE_DESTRUCT_RE = re.compile(
    r"""(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\(\s*["']([^"']+)["']\s*\)"""
)
_REQUIRE_MEMBER_RE = re.compile(
    r"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*["']([^"']+)["']\s*\)\.([A-Za-z_$][\w$]*)"""
)
_EXPORT_LIST_RE = re.compile(r"""export\s*\{([^}]+)\}""")
_EXPORT_ASSIGN_RE = re.compile(r"""(?:module\.)?exports\.([A-Za-z_$][\w$]*)\s*=\s*(.+)$""")


_STRING_LITERAL_RE = re.compile(r"""(['"`])(?:\\.|(?!\1).)*\1""")


def _strip_strings(text: str) -> str:
    return _STRING_LITERAL_RE.sub('""', text)


def _source_kind(text: str, taints: dict[str, str]) -> str | None:
    for kind, pattern in _SOURCE_PATTERNS:
        if pattern.search(text):
            return kind
    stripped = _strip_strings(text)
    for variable, source in taints.items():
        if re.search(rf"\b{re.escape(variable)}\b", stripped):
            return source
    return None


def _resolve_module(module: str, spec: str, sources: dict[str, str]) -> str | None:
    if not spec.startswith("."):
        return None
    base = posixpath.normpath(posixpath.join(posixpath.dirname(module), spec))
    candidates = [
        base,
        f"{base}.js",
        f"{base}.mjs",
        f"{base}.cjs",
        f"{base}.jsx",
        f"{base}.ts",
        f"{base}.tsx",
        f"{base}/index.js",
        f"{base}/index.ts",
    ]
    for candidate in candidates:
        normalized = candidate.lstrip("./")
        if normalized in sources:
            return normalized
    return None


def _module_exports(sources: dict[str, str]) -> dict[tuple[str, str], str]:
    exports: dict[tuple[str, str], str] = {}
    local_sources: dict[str, dict[str, str]] = {}
    for module, text in sorted(sources.items()):
        locals_: dict[str, str] = {}
        for line in text.splitlines():
            assignment = _ASSIGN_RE.search(line)
            if assignment is not None:
                source = _source_kind(line[assignment.end() :], locals_)
                if source is not None:
                    name = assignment.group(1)
                    locals_[name] = source
                    if line.lstrip().startswith("export "):
                        exports[(module, name)] = source
            export_assign = _EXPORT_ASSIGN_RE.search(line)
            if export_assign is not None:
                source = _source_kind(export_assign.group(2), locals_)
                if source is not None:
                    exports[(module, export_assign.group(1))] = source
            default_export = re.match(r"export\s+default\s+(.+)$", line.strip())
            if default_export is not None:
                source = _source_kind(default_export.group(1), locals_)
                if source is not None:
                    exports[(module, "default")] = source
        local_sources[module] = locals_
    for module, text in sorted(sources.items()):
        for match in _EXPORT_LIST_RE.finditer(text):
            for part in match.group(1).split(","):
                pieces = part.strip().split()
                if not pieces:
                    continue
                local_name = pieces[0]
                export_name = pieces[-1] if len(pieces) >= 3 else local_name
                source = local_sources[module].get(local_name)
                if source is not None and (module, export_name) not in exports:
                    exports[(module, export_name)] = source
    return exports


def _imported_taints(
    sources: dict[str, str], exports: dict[tuple[str, str], str]
) -> dict[str, dict[str, str]]:
    imported: dict[str, dict[str, str]] = {}
    for module, text in sorted(sources.items()):
        taints: dict[str, str] = {}
        for match in _IMPORT_NAMED_RE.finditer(text):
            target = _resolve_module(module, match.group(2), sources)
            if target is None:
                continue
            for part in match.group(1).split(","):
                pieces = part.strip().split()
                if not pieces:
                    continue
                exported = pieces[0]
                local = pieces[-1] if len(pieces) >= 3 else exported
                source = exports.get((target, exported))
                if source is not None:
                    taints[local] = source
        for match in _IMPORT_DEFAULT_RE.finditer(text):
            target = _resolve_module(module, match.group(2), sources)
            source = exports.get((target or "", "default"))
            if source is not None:
                taints[match.group(1)] = source
        for match in _REQUIRE_DESTRUCT_RE.finditer(text):
            target = _resolve_module(module, match.group(2), sources)
            if target is None:
                continue
            for part in match.group(1).split(","):
                pieces = part.strip().split(":")
                if not pieces:
                    continue
                exported = pieces[0].strip()
                local = pieces[-1].strip() if len(pieces) > 1 else exported
                source = exports.get((target, exported))
                if source is not None:
                    taints[local] = source
        for match in _REQUIRE_MEMBER_RE.finditer(text):
            target = _resolve_module(module, match.group(2), sources)
            source = exports.get((target or "", match.group(3)))
            if source is not None:
                taints[match.group(1)] = source
        imported[module] = taints
    return imported


def _dataflow(sources: dict[str, str], parameters: dict[str, Any]) -> dict[str, Any]:
    operations: list[dict[str, Any]] = []
    flows: list[dict[str, Any]] = []
    sinks: list[dict[str, Any]] = []
    exports = _module_exports(sources)
    imported = _imported_taints(sources, exports)
    for module, text in sorted(sources.items()):
        lines = text.splitlines()
        taints: dict[str, str] = dict(imported.get(module, {}))
        for line_number, line in enumerate(lines, 1):
            for kind, pattern in _STORAGE_PATTERNS:
                for match in pattern.finditer(line):
                    groups = [group for group in match.groups() if group]
                    operations.append(
                        {
                            "module": module,
                            "line": line_number,
                            "kind": kind,
                            "name": groups[-1] if groups else None,
                        }
                    )
            for kind, pattern in _SINK_PATTERNS:
                for _match in pattern.finditer(line):
                    sinks.append({"module": module, "line": line_number, "kind": kind})
            assignment = _ASSIGN_RE.search(line)
            if assignment is not None:
                name = assignment.group(1)
                source = _source_kind(line[assignment.end() :], taints)
                if source is not None:
                    taints[name] = source
            stripped_line = _strip_strings(line)
            for variable, source in list(taints.items()):
                if not re.search(rf"\b{re.escape(variable)}\b", stripped_line):
                    continue
                for sink_kind, pattern in _SINK_PATTERNS:
                    if pattern.search(line):
                        flows.append(
                            {
                                "module": module,
                                "line": line_number,
                                "source": source,
                                "sink": sink_kind,
                                "variable": variable,
                            }
                        )
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for row in flows:
        key = (row["module"], row["line"], row["source"], row["sink"], row["variable"])
        if key not in seen:
            seen.add(key)
            deduped.append(row)
    flow_page = page_sequence(
        deduped,
        offset=int(parameters.get("offset") or 0),
        limit=int(parameters.get("limit") or 200),
    )
    operation_page = page_sequence(
        operations,
        offset=int(parameters.get("operation_offset") or 0),
        limit=int(parameters.get("operation_limit") or 200),
    )
    sink_page = page_sequence(
        sinks,
        offset=int(parameters.get("sink_offset") or 0),
        limit=int(parameters.get("sink_limit") or 200),
    )
    return {
        "operation_count": len(operations),
        "operation_offset": operation_page["offset"],
        "next_operation_offset": operation_page["next_offset"],
        "operations": operation_page["items"],
        "flow_count": len(deduped),
        "flow_offset": flow_page["offset"],
        "next_flow_offset": flow_page["next_offset"],
        "flows": flow_page["items"],
        "sink_count": len(sinks),
        "sink_offset": sink_page["offset"],
        "next_sink_offset": sink_page["next_offset"],
        "sinks": sink_page["items"],
        "exported_source_count": len(exports),
        "imported_source_count": sum(len(value) for value in imported.values()),
        "truncated": len(operations) >= 5000 or len(sinks) >= 5000,
    }


_BASE64 = {
    char: index
    for index, char in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
}


def _decode_mappings(mappings: Any) -> dict[str, Any]:
    if not isinstance(mappings, str):
        return {"mapping_count": 0, "generated_line_count": 0, "lines": []}
    lines: list[list[list[int]]] = []
    generated_line = 0
    source = original_line = original_column = name = 0
    count = 0
    for line_text in mappings.split(";"):
        line: list[list[int]] = []
        generated_column = 0
        for segment_text in line_text.split(","):
            if not segment_text:
                continue
            values = _vlq(segment_text)
            if len(values) not in (1, 4, 5):
                continue
            generated_column += values[0]
            entry = [generated_column]
            if len(values) >= 4:
                source += values[1]
                original_line += values[2]
                original_column += values[3]
                entry.extend([source, original_line, original_column])
                if len(values) == 5:
                    name += values[4]
                    entry.append(name)
            line.append(entry)
            count += 1
        lines.append(line)
        generated_line += 1
    return {
        "mapping_count": count,
        "generated_line_count": generated_line,
        "lines": lines,
    }


def _vlq(text: str) -> list[int]:
    values: list[int] = []
    value = shift = 0
    for char in text:
        digit = _BASE64.get(char)
        if digit is None:
            continue
        value |= (digit & 31) << shift
        if digit & 32:
            shift += 5
            continue
        negative = value & 1
        value >>= 1
        values.append(-value if negative else value)
        value = shift = 0
    return values


def _lookup_mapping(lines: list[list[list[int]]], line: int, column: int) -> dict[str, Any] | None:
    if line < 0 or line >= len(lines):
        return None
    selected = None
    for entry in lines[line]:
        if entry[0] > column:
            break
        selected = entry
    if selected is None or len(selected) < 4:
        return None
    return {
        "source": selected[1],
        "original_line": selected[2],
        "original_column": selected[3],
        "name": selected[4] if len(selected) > 4 else None,
    }


def _routes(sources: dict[str, str], parameters: dict[str, Any]) -> dict[str, Any]:
    routes: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str, str]] = set()
    for name in sorted(sources):
        text = sources[name]
        for line_number, line in enumerate(text.splitlines(), 1):
            for kind, pattern in _ROUTE_PATTERNS:
                for match in pattern.finditer(line):
                    path = match.group(1)
                    method = "fetch" if kind == "fetch" else "path" if kind == "path" else "route"
                    key = (name, line_number, method, path)
                    if key in seen:
                        continue
                    seen.add(key)
                    routes.append(
                        {
                            "file": name,
                            "line": line_number,
                            "kind": kind,
                            "method": method,
                            "path": path,
                        }
                    )
                    if len(routes) >= 1000:
                        break
                if len(routes) >= 1000:
                    break
            if len(routes) >= 1000:
                break
        if len(routes) >= 1000:
            break
    page = page_sequence(
        routes,
        offset=int(parameters.get("offset") or 0),
        limit=int(parameters.get("limit") or 200),
    )
    by_kind: dict[str, int] = {}
    for route in routes:
        by_kind[route["kind"]] = by_kind.get(route["kind"], 0) + 1
    return {
        "route_count": len(routes),
        "offset": page["offset"],
        "next_offset": page["next_offset"],
        "routes": page["items"],
        "by_kind": by_kind,
        "truncated": len(routes) >= 1000,
    }


__all__ = ["JavaScriptApplicationProvider"]
