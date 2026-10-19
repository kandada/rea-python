# rea-python(rea-mcp)

**Reverse engineer anything from your terminal or agent — one CLI and one MCP server.**

## Attribution and disclaimer

> This is an unofficial Python port of morluto/rea. The original project is a TypeScript implementation. This port exists because our Python-based AI agent products (aacode, fastclaw) need a native Python integration. Not affiliated with or endorsed by the original authors. Licensed under MIT.

See [DISCLAIMER.md](DISCLAIMER.md) for responsible-use guidance and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for dependency and tool notices.

### Lawful use

The project's position on illegal or unauthorized use covers all REA versions, distribution channels, and platforms; each copy retains its applicable licenses.

REA is for lawful research, education, interoperability, software preservation, and analysis of software you own or are authorized to examine.

### Commercial tools

You must legally obtain and be authorized to use commercial tools, including IDA Pro / Hex-Rays decompilers, Hopper, and JEB, under their applicable licenses. REA grants no tool license, key, or activation entitlement. Trials and demos remain subject to vendor terms, including user, feature, automation, and output sharing restrictions. Cracked copies, stolen keys, unauthorized key sharing, and bypassing license restrictions are not authorized. This guidance does not amend MIT or third-party licenses.

### Deep-engine configuration

| Engine | Configure | Notes |
|---|---|---|
| IDA | `REA_IDA_MCP_CONFIG` (an `ida-pro-mcp` registration JSON), or `REA_IDA_MCP_URL` / `REA_IDA_MCP_COMMAND` | Speaks MCP over stdio or streamable HTTP |
| JEB | `REA_JEB_MCP_URL` (default `http://127.0.0.1:8425/mcp`) | MCP streamable HTTP |
| Hopper | `REA_HOPPER_BRIDGE` (socket) and `REA_HOPPER_BRIDGE_TOKEN` (run token) | Run `bridge/hopper_bridge.py` inside Hopper |
| Kuna | `REA_KUNA_COMMAND` (absolute path), optional `REA_KUNA_TIMEOUT_MS` | Invokes `kuna decompile ...` |
| Ghidra | `GHIDRA_INSTALL_DIR`, `JAVA_HOME`; optional `REA_GHIDRA_BRIDGE=pyhidra\|pyghidra` | Auto-selects pyhidra (≤11.3) or pyghidra (≥11.4) |
| Frida | Attach by PID/process name; `--spawn --allow-execute` to launch | Needs `task_for_pid` permission |
| macOS UI automation | `--allow-ui` | Needs Accessibility permission |

rea-python is a provider-neutral reverse-engineering engine that returns traceable, evidence-carrying, reusable results, exposed through a shared CLI and MCP (Model Context Protocol) server. Its design follows the ideas behind [morluto/rea](https://github.com/morluto/rea), including the Evidence model: every result carries its identity, confidence, authority, limitations, and unresolved unknowns, so an AI agent (or a person) can reason honestly instead of trusting a bare answer.

> Status: **alpha (0.1.6)** — full original CLI/MCP surface (169 tool names, 153 CLI commands) with built-in static providers, the Evidence model, snapshot caching, deep-engine adapters, workflow/evidence tools, and gated runtime observation.

## Upstream sync

rea-python tracks [morluto/rea](https://github.com/morluto/rea). As of **0.1.6** it matches the **6.7.0** tool surface (169 MCP tools, 153 CLI commands) and adopts these 6.6/6.7 behaviors:

- Apktool localized string tables: repeatable `--locales`, `--locale`, `--string-tables-only`
- JADX whole-operation deadline: `REA_JADX_OPERATION_TIMEOUT_MS`
- Setup merges into existing JSON/JSONC client configs instead of overwriting unrelated servers
- Ghidra bridge auto-selection: `pyhidra` (Ghidra ≤11.3) or `pyghidra` (Ghidra ≥11.4), with `--language`/`--compiler`
- Kuna multi-operation provider: procedures, strings, xrefs, pseudocode, callers/callees, assembly via project export, with inventory/string caching
- Retained analysis views: `environment-manifest`, `javascript-facts`, `javascript`
- Prompt process cancellation with partial output; ASAR integrity observations; DMG inspection and read-only extraction
- Universal (fat) Mach-O inspection, code-signature metadata, and address-mapped byte tools

Known depth gaps vs upstream: full Kuna project-export reuse, Electron inspector/listener-ownership refinements, and exact upstream raw-image preparation semantics.

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
| Android deep | apktool resources/smali, JADX class/APK decompilation | apktool / JADX + JRE |
| Android device | Devices, packages, package dumps, bounded shell | adb + device |
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
| Saved captures (pcap) | Packet fields, endpoints, DNS queries | built-in (tshark enriches) |
| Firmware images | Region/signature scan | built-in (binwalk enriches) |
| Web runtime | Page DOM, scripts, event handlers, screenshots, scenarios | playwright + Chromium |
| Electron / JS runtime | CDP targets, pages, runtime reconciliation | CDP endpoint |
| Debug sessions | GDB batch console, Rizin debug, Cutter bridge | gdb / rizin / Cutter bridge |
| Native proxy | Navigation, comments, names, procedures, xrefs | Rizin |
| Android deep | JADX class/method/reference search | JADX + JRE |
| Workflows | Call graph/path, feature trace, bundle and capture diffs | built-in |
| Mach-O signatures | CodeDirectory, CDHash, team/identifier, entitlements | built-in |
| Byte tools | Address-mapped reads and byte-pattern search | built-in |
| Application graphs | Android components/permissions, Apple bundles, Harmony abilities | built-in |
| Digital signals (VCD) | Signal inventory and 8N1 UART decode | built-in |
| Crash dumps | GDB/pwndbg register and backtrace summary | built-in |
| Apple bundles | Entitlements, keyed archive, Interface Builder, asset catalog | built-in |
| Electron apps | Fuse-wire security posture | built-in |
| Reconstruction | Obligation ledger and coverage evaluation | built-in |
| Native disassembly | File/section headers | objdump |
| Deep native analysis | Overview, functions, pseudocode, xrefs, search | Rizin (rzpipe) |
| Ghidra | Functions and pseudocode | pyhidra (Ghidra ≤11.3) or pyghidra (Ghidra ≥11.4) + JDK |
| Hopper | Overview, functions, pseudocode, xrefs | Hopper + bridge/hopper_bridge.py |
| IDA / JEB | Overview, functions, pseudocode, xrefs over HTTP | REA_IDA_MCP_URL / REA_JEB_MCP_URL |
| Frida | Devices, applications, processes | frida |
| Browser | Page observation | playwright + REA_BROWSER_EXECUTABLE |
| CDP runtime (Chrome/Electron) | Target inventory, live network metadata | built-in HTTP (websocket-client for capture) |
| Recorded crashes | Register/signal extraction | REA_PWNTOOLS_PYTHON + pwntools |

External-tool providers are caller-supplied: rea-mcp never installs them and reports an actionable reason when one is missing (`rea-mcp doctor`). Cross-cutting tools: `compare` / `compare-network-captures` / `compare-web-captures` / `compare-managed-members` (target and Evidence diffs), `build-reconstruction-obligation-ledger` / `evaluate-reconstruction-coverage` (reconstruction), `capture-process` (bounded runtime capture), `doctor` (readiness), `setup` (client registration, plus `--write-all` and `--install-skill`), `update`, and `evidence-export` / `evidence-import` / `inspect-analysis-view` (portable Evidence).

All analysis runs locally. rea-mcp never uploads your target.

## Client schema profiles

Tool schemas can be projected per client to fit hosts with small frame or schema limits. Set `REA_MCP_CLIENT` to a preset (`generic`, `claude`, `cursor`, `opencode`, `vscode`/`code`, `zed`, `minimal`), or override with `REA_MCP_INPUT_SCHEMA_PROFILE` (`full`/`compact`) and `REA_MCP_OUTPUT_SCHEMA_PROFILE` (`full`/`off`). `rea-mcp schema-matrix` prints the full matrix; `REA_MCP_COMPACT_BUDGET_BYTES` caps a single compacted schema.

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
import rea_mcp  # implementation
import rea  # alias, same objects
import rea_python  # alias, same objects
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

## Releasing

- **CI** runs on branch pushes, pull requests, and manual dispatch. Tag pushes and GitHub Release creation do **not** trigger CI.
- **PyPI** publishing is local only: `twine upload dist/*`. This repository intentionally contains **no CI publishing workflow**, so creating a GitHub Release never publishes to PyPI.

## License

MIT. rea-mcp is an independent, unofficial Python port; it is not affiliated with or endorsed by the authors of REA. See [LICENSE](LICENSE) and [DISCLAIMER.md](DISCLAIMER.md).
