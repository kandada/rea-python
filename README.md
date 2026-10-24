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

> Status: **alpha (0.1.53)** — the original 169 upstream MCP tool names and 153 CLI commands, plus compatibility/extras (265 MCP tools, 289 CLI commands) with built-in static providers, the Evidence model, snapshot caching, deep-engine adapters, workflow/evidence tools, and gated runtime observation.

## Upstream sync

rea-python tracks [morluto/rea](https://github.com/morluto/rea). As of **0.1.53** it matches the **6.7.0** upstream tool surface (169 MCP tools, 153 CLI commands) and adopts these 6.6/6.7 behaviors:

- Apktool localized string tables: repeatable `--locales`, `--locale`, `--string-tables-only`
- JADX whole-operation deadline: `REA_JADX_OPERATION_TIMEOUT_MS`
- Setup merges into existing JSON/JSONC client configs instead of overwriting unrelated servers
- Ghidra bridge auto-selection: `pyhidra` (Ghidra ≤11.3) or `pyghidra` (Ghidra ≥11.4), with `--language`/`--compiler`
- Kuna multi-operation provider: procedures, strings, xrefs, pseudocode, callers/callees, assembly via project export, with inventory/string caching
- Retained analysis views: `environment-manifest`, `javascript-facts`, `javascript`
- Prompt process cancellation with partial output; ASAR integrity observations; DMG inspection and read-only extraction
- Universal (fat) Mach-O inspection, code-signature metadata, and address-mapped byte tools

Known depth gaps vs upstream: full Kuna project-export reuse and Electron inspector/listener-ownership refinements.

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
| JavaScript / Electron | Module graph, IPC boundaries, routes, source maps, WebMCP, storage/DOM dataflow (directory or ASAR) | built-in |
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
| Agent environments | Capture manifest/replay, derived state, compare, writes, bundle export and HTTP serving | built-in |
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

Engine tools can live on an external volume. Kuna is auto-detected under `vendor/tools/kuna-*/kuna-*/kuna`, or set `REA_KUNA_COMMAND` to the absolute binary. Raw images are selected with `raw_image`/`--raw-image` plus `target`/`base`/`entry`:

```bash
rea list-procedures firmware.bin --raw-image --target x86:LE:64:default --base 0x100000000 --entry 0x100000010
rea kuna-decompile firmware.bin --raw-image --target x86:LE:64:default --base 0x100000000 --entry 0x100000010 --function sub_100000010
```

An Electron runtime is auto-detected under `vendor/tools/electron/node_modules/.bin/electron` (or `REA_ELECTRON_EXECUTABLE`). `capture-electron-scenario --app DIR` launches the app, discovers a free CDP port, runs the scenario, and terminates the process:

```bash
rea capture-electron-scenario --app ./electron-app --steps-json '[{"action":"screenshot","path":"shot.png"}]'
```

External-tool providers are caller-supplied: rea-mcp never installs them and reports an actionable reason when one is missing (`rea-mcp doctor`). Cross-cutting tools: `compare` / `compare-network-captures` / `compare-web-captures` / `compare-managed-members` (target and Evidence diffs), `build-reconstruction-obligation-ledger` / `evaluate-reconstruction-coverage` (reconstruction), `capture-process` (bounded runtime capture), `doctor` (readiness), `setup` (client registration, plus `--write-all` and `--install-skill`), `update`, and `evidence-export` / `evidence-import` / `inspect-analysis-view` (portable Evidence).

Agent environments are an extension beyond the 6.7.0 upstream surface. From an `environment-manifest` Evidence record and its parent capture:

```bash
rea environment-compare manifest.json capture.json --probe probe.json
rea environment-export manifest.json capture.json ./bundle
rea environment-serve manifest.json capture.json --port 18765
```

The exporter derives item/list/document state, writes a Dockerfile and verifier, and the server exposes manifest tools plus replay/state/compare tools and `/agentenv/data/{get,list,add,merge,delete,document,reset}`.

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

## Readiness and client setup

```bash
rea-mcp doctor          # providers, external tools, effective timeouts
rea-mcp setup           # print the MCP client registration plan
rea-mcp setup --write <client-config.json>   # merge into an existing JSON/JSONC config
rea-mcp setup --install-skill <dir>          # install the bundled agent skill
```

`doctor` lists each provider, its operations, and why an optional engine is unavailable. It does not install anything.

## Response budgets

MCP results are capped at 512 KiB by default (`REA_MCP_MAX_RESPONSE_BYTES`). Oversized analysis results are retained as Evidence and returned as a compact summary with an `evidence_reference`; use `evidence-export`, `inspect-analysis-view --view record --evidence-id <id>`, or `get-evidence-bundle --full` for the complete data. Set a CLI budget with `--output-budget <bytes>`; an oversized CLI result is written to a UTF-8 JSON file and stdout receives a summary plus `output_path`. `inspect-analysis-view`, `inspect-artifact`, `inspect-managed-members`, `inspect-network-capture`, `inspect-android-package`, `inspect-android-class`, `inspect-android-method`, `decompile-android-apk`, `decompile-android-class`, and `analyze-javascript-application` page with `--offset`/`--limit` (JavaScript also has `--module-offset`/`--edge-offset`). Decompilers return a summary-sized preview by default; `--max-bytes` changes the limit and the full text remains in Evidence. `batch-decompile` caps pseudocode at 64 KiB per function (`--max-bytes-per-function 0` disables the cap). Captured web response bodies are capped at 32 KiB each and 512 KiB total; `observe-web-execution --bodies --retain-bodies` keeps the complete bodies in Evidence (up to 8 MiB) while returning bounded previews.

For managed assemblies, `inspect-managed-members --type <full-name> --detail summary --evidence-bundle <file>` writes the complete parent Evidence and prints identity, selection, counts and coverage. Page individual collections afterwards with `inspect-analysis-view <file> --view managed-members --collection types|fields|methods|member_refs|call_edges|field_accesses|field_initializers|user_strings --offset/--limit`; `inspect-managed-artifact --detail summary` exposes module/MVID, assembly, references, resources and attributes. Additional static providers include `inspect-elf-notes`, `inspect-erlang-beam`, `inspect-pe-certificates`, `inspect-native-exports`, `inspect-javascript-routes`, `inspect-apk-signature`, `inspect-byte-entropy`, `inspect-python-pyc`, `inspect-model-artifact`, `inspect-desktop-application`, `inspect-gpu-code-objects`, `inspect-il2cpp-metadata`, `read-bytes`, `search-bytes` and `address-to-file-offset`. `compare-managed-members` now compares types, fields, methods and nesting by exact type/name/signature identity. Optional C# decompilation is available through `decompile-managed-csharp` when `ilspycmd` is on `PATH` or `REA_ILSPY`/`REA_ILSPY_CMD_PATH` points to it. Managed metadata parsing uses a bounded in-process cache (`REA_MANAGED_CACHE_ENTRIES`, default 8); set it to `0` to disable. `doctor --required dotnet,artifacts,sqlite --strict` (or `--profile powerbi`) separates core readiness from optional engines. `rea mcp --transport streamable-http --host 127.0.0.1 --port 8000 --path /mcp` opts into HTTP transport; stdio remains the default.

The optional `rea upstream ...` command forwards to a caller-installed upstream Node package (`REA_UPSTREAM_CLI`) for features not yet ported to Python.

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

## License

MIT. rea-mcp is an independent, unofficial Python port; it is not affiliated with or endorsed by the authors of REA. See [LICENSE](LICENSE) and [DISCLAIMER.md](DISCLAIMER.md).
