# rea-python(rea-mcp)

**Reverse engineer anything from your terminal or agent — one CLI and one MCP server.**

## Attribution and disclaimer

> This is an unofficial Python port of morluto/rea. The original project is a TypeScript implementation. This port exists because our Python-based AI agent products (aacode, fastclaw) need a native Python integration. Not affiliated with or endorsed by the original authors. Licensed under MIT.

See [DISCLAIMER.md](DISCLAIMER.md) for responsible-use guidance and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for dependency and tool notices.

rea-python is a provider-neutral reverse-engineering engine that returns traceable, evidence-carrying, reusable results, exposed through a shared CLI and MCP (Model Context Protocol) server. Its design follows the ideas behind [morluto/rea](https://github.com/morluto/rea), including the Evidence model: every result carries its identity, confidence, authority, limitations, and unresolved unknowns, so an AI agent (or a person) can reason honestly instead of trusting a bare answer.

> Status: **alpha (0.1.1)** — static-analysis MVP with built-in static providers, the Evidence model, snapshot caching, and the shared CLI/MCP surface.

## What you can analyze

| Target | What rea-mcp returns | Requires |
|---|---|---|
| ELF / PE / Mach-O | Sections, segments, entrypoint, symbols, exports/imports, mitigations | built-in |
| Go binaries | Embedded compiler version, modules, replacements, build settings | built-in |
| Rust binaries | cargo-auditable dependency inventory and edges | built-in |
| .NET assemblies | PE/CLI metadata, member names, per-method IL disassembly | built-in |
| SQLite databases | Tables, columns, indexes, views, triggers | built-in |
| Zip / tar / ASAR packages | File inventory and digests | built-in |
| Android APK | Zip inventory, DEX headers, manifest package facts | built-in |
| Flutter apps | Dart AOT snapshot fingerprint and URI counts per ABI | built-in |
| WASM modules | Validation, sections, decoded WAT | built-in (WAT needs WABT) |
| Property lists | XML/binary plist and NSKeyedArchiver inventory | built-in |
| HarmonyOS HAP | Package facts and entry hashes | built-in |
| JavaScript / Electron | Module graph and IPC boundaries (directory or ASAR) | built-in |
| PE resources | Resource types and counts | built-in |
| Reference source | Source-tree inventory: files, sizes, digests, languages | built-in |
| EVM bytecode | Dispatch selectors, arguments, mutability | evmole |
| Network captures | HAR/SAZ requests, hosts, status | built-in |
| Live traffic | Capture through a proxy | mitmproxy |
| Saved captures (pcap) | Protocol hierarchy and endpoints | tshark |
| Firmware images | Region/signature scan | binwalk |
| Native disassembly | File/section headers | objdump |
| Deep native analysis | Overview, functions, pseudocode, xrefs, search | Rizin (rzpipe) |
| Ghidra | Functions and pseudocode | pyhidra + Ghidra + JDK |
| Hopper | Overview, functions, pseudocode, xrefs | Hopper + bridge/hopper_bridge.py |
| IDA / JEB | Endpoint probe | REA_IDA_MCP_URL / REA_JEB_MCP_URL |
| Frida | Device inventory | frida |
| Browser | Page observation | playwright + REA_BROWSER_EXECUTABLE |
| Recorded crashes | Register/signal extraction | REA_PWNTOOLS_PYTHON + pwntools |

External-tool providers are caller-supplied: rea-mcp never installs them and reports an actionable reason when one is missing (`rea-mcp doctor`). Cross-cutting tools: `compare` (Evidence diff), `capture-process` (bounded runtime capture), `doctor` (readiness), `setup`, `update`, and `evidence-export` / `evidence-import` / `inspect-analysis-view` (portable Evidence).

All analysis runs locally. rea-mcp never uploads your target.

## Quick start

```bash
pip install rea-mcp             # PyPI distribution name is "rea-mcp"
rea-mcp --help                  # "rea" and "rea-python" are installed as alias commands too
rea-mcp inspect-binary-layout /path/to/program --json
```

As an MCP server (stdio) — `rea-mcp`, `rea`, and `rea-python` are interchangeable, as are `python -m rea_mcp`, `python -m rea`, and `python -m rea_python`:

```bash
rea-mcp mcp     # or: rea mcp   |   rea-python mcp
rea mcp
```

Output is JSON by default; a bare `--json` flag is accepted (before or after the command) for compatibility.

## Import names

The implementation package is `rea_mcp`. Compatibility aliases make `import rea` and `import rea_python` resolve to the same module objects, so all three import paths are interchangeable:

```python
import rea_mcp      # implementation
import rea          # alias, same objects
import rea_python   # alias, same objects
```

## Design principles

1. **Dependencies flow inward**: domain → contracts → providers → application → cli/mcp.
2. **Evidence first**: observations, derivations, inferences, and unknowns are distinguished.
3. **Ownership and cleanup**: resources are only cleaned by their owner; failures stay explicit.
4. **Token-first performance**: summaries, paging, and retained evidence keep agent context small.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check .
mypy
```

## License

MIT. rea-mcp is an independent, unofficial Python port; it is not affiliated with or endorsed by the authors of REA. See [LICENSE](LICENSE) and [DISCLAIMER.md](DISCLAIMER.md).
