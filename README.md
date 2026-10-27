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

> Status: **alpha (0.1.56)** — the original 169 upstream MCP tool names and 153 CLI commands, plus compatibility/extras (266 MCP tools, 293 CLI commands) with built-in static providers, the Evidence model, snapshot caching, deep-engine adapters, workflow/evidence tools, and gated runtime observation.

## Upstream sync

rea-python tracks [morluto/rea](https://github.com/morluto/rea). As of **0.1.56** it matches the **6.7.0** upstream tool surface (169 MCP tools, 153 CLI commands) and adopts these 6.6/6.7 behaviors:

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

## Agent modes and context budget

REA-Python is optimized for both skill-first and MCP workflows. The full MCP catalog is large, so it is opt-in:

```bash
rea triage /path/to/target                         # compact, format-aware first pass
rea mcp                                            # core toolset by default
rea mcp --toolset native                           # native-binary tools + core
rea mcp --toolset web,android                      # compose domains
rea mcp --toolset full                             # complete compatibility catalog
rea mcp --available-only                           # hide providers that are not installed
```

Measured with `REA_MCP_CLIENT=minimal` and `cl100k_base`:

| Mode | Tools | Schema tokens |
|---|---:|---:|
| core | 19 | ~1.7k |
| native | 73 | ~6.2k |
| web | 53 | ~4.8k |
| android | 61 | ~5.3k |
| managed | 30 | ~2.8k |
| full | 266 | ~23.3k |
| bundled skill | 0 | ~2.3k |

The bundled `skill.md` is a routing guide for CLI-first work. `rea triage` returns facts, limitations, evidence IDs and `next_probes` in one compact call. Use `python benchmarks/measure_schema.py` to reproduce the table, `python benchmarks/run_task_benchmark.py --target native=/bin/ls` for task-level turns/tokens/time, and `benchmarks/README.md` for the agent task methodology.

## Client schema profiles

Tool schemas can be projected per client to fit hosts with small frame or schema limits. Set `REA_MCP_CLIENT` to a preset (`generic`, `claude`, `cursor`, `opencode`, `vscode`/`code`, `zed`, `minimal`), or override with `REA_MCP_INPUT_SCHEMA_PROFILE` (`full`/`compact`) and `REA_MCP_OUTPUT_SCHEMA_PROFILE` (`full`/`off`). `rea-mcp schema-matrix` prints the full matrix; `REA_MCP_COMPACT_BUDGET_BYTES` caps a single compacted schema. Agent presets (`cursor`, `opencode`, `vscode`, `zed`, `minimal`) default to compact input, no output schema, and the core toolset; `REA_MCP_TOOLSET` and `REA_MCP_AVAILABLE_ONLY` control the advertised catalog. Use `rea manifest` for a compact command catalog and `rea schema <command>` for one command's arguments.

## Quick start

```bash
pip install rea-mcp             # PyPI distribution name is "rea-mcp"
rea-mcp --help                  # "rea" and "rea-python" are installed as alias commands too
rea-mcp inspect-binary-layout /path/to/program --json
rea triage /path/to/program                          # one compact first pass
```

As an MCP server (stdio) — `rea-mcp`, `rea`, and `rea-python` are interchangeable, as are `python -m rea_mcp`, `python -m rea`, and `python -m rea_python`:

```bash
rea-mcp mcp     # or: rea mcp   |   rea-python mcp
rea mcp         # core toolset
rea mcp --toolset full
```

Output is JSON by default; a bare `--json` flag is accepted (before or after the command) for compatibility.

## Readiness and client setup

```bash
rea-mcp doctor          # providers, external tools, effective timeouts
rea-mcp setup           # print the MCP client registration plan
rea-mcp setup --mode hybrid --toolset core --install-skill <skills-dir> --write <client-config.json>
rea-mcp setup --mode skill --install-skill <skills-dir>   # skill only, no MCP
rea-mcp setup --mode full --write <client-config.json>    # compatibility catalog
```

OpenCode paths are detected automatically and use the `mcp.<name>` local-server shape; other clients use `mcpServers`. For a token-sensitive OpenCode setup:

```bash
rea setup --mode hybrid --toolset core --install-skill ~/.config/opencode/skills
rea setup --mode core --write ~/.config/opencode/opencode.json
```

`doctor` lists each provider, its operations, and why an optional engine is unavailable. It does not install anything.

## Agent client configuration examples

Different clients use different MCP config keys. The table is the practical
starting point; check your client version if it has recently changed its schema.

| Client | Typical config | Server key |
|---|---|---|
| OpenCode | `~/.config/opencode/opencode.json` | `mcp` |
| Claude Code / Desktop | `.mcp.json` or `claude_desktop_config.json` | `mcpServers` |
| Cursor | `~/.cursor/mcp.json` | `mcpServers` |
| VS Code | `.vscode/mcp.json` | `servers` |
| Codex CLI | `~/.codex/config.toml` | `mcp_servers` |
| Gemini CLI | `~/.gemini/settings.json` | `mcpServers` |

Format sources (checked against current vendor documentation; client versions can
change their schema):

- OpenCode: [MCP servers](https://opencode.ai/docs/mcp-servers/)
- Claude Code: [MCP configuration](https://code.claude.com/docs/en/mcp)
- Cursor: [Model Context Protocol](https://docs.cursor.com/context/mcp)
- VS Code: [MCP servers](https://code.visualstudio.com/docs/copilot/customization/mcp-servers)
- Codex CLI: [configuration reference](https://developers.openai.com/codex/config-reference)
- Gemini CLI: [MCP server configuration](https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md)
- AACode: [system prompt integration](https://github.com/kandada/aacode/blob/main/core/prompts.py)

`rea setup --write ...` auto-detects OpenCode and otherwise writes the common
`mcpServers` shape used by Claude/Cursor. VS Code (`servers`), Codex
(`mcp_servers` in TOML) and Gemini (`settings.json`) examples are intentionally
manual because their config containers differ. Always restart the client after
editing.

For token-sensitive use, start with `core` and add domains only when needed. The
same `REA_MCP_CLIENT` / `REA_MCP_TOOLSET` values are used in every example.

### OpenCode: hybrid (recommended)

Install the routing skill and register a core MCP server in one step:

```bash
rea setup --mode hybrid --toolset core \
  --install-skill ~/.config/opencode/skills \
  --write ~/.config/opencode/opencode.json
```

The resulting config is:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "rea": {
      "type": "local",
      "command": ["rea-mcp", "mcp", "--toolset", "core"],
      "enabled": true,
      "environment": {
        "REA_MCP_CLIENT": "opencode",
        "REA_MCP_TOOLSET": "core"
      }
    }
  }
}
```

Core is enough for triage, inventory, strings, search, decompile, xrefs and
Evidence. Add `"web"`, `"android"`, `"managed"` or `"full"` to
`REA_MCP_TOOLSET` when the task needs those domains. For an even smaller setup,
use skill-only mode and let the agent call `rea` directly:

```bash
rea setup --mode skill --install-skill ~/.config/opencode/skills
rea triage /path/to/target
```

### Claude Code / Claude Desktop

```json
{
  "mcpServers": {
    "rea": {
      "command": "rea-mcp",
      "args": ["mcp", "--toolset", "core"],
      "env": {
        "REA_MCP_CLIENT": "claude",
        "REA_MCP_TOOLSET": "core"
      }
    }
  }
}
```

Or generate/merge it:

```bash
rea setup --mode core --client claude --write .mcp.json
```

### Cursor

```json
{
  "mcpServers": {
    "rea": {
      "command": "rea-mcp",
      "args": ["mcp", "--toolset", "native"],
      "env": {
        "REA_MCP_CLIENT": "cursor",
        "REA_MCP_TOOLSET": "native"
      }
    }
  }
}
```

`rea setup --mode core --write ~/.cursor/mcp.json` merges the same block
automatically.

### VS Code

VS Code uses `servers`, not `mcpServers`:

```json
{
  "servers": {
    "rea": {
      "type": "stdio",
      "command": "rea-mcp",
      "args": ["mcp", "--toolset", "core"],
      "env": {
        "REA_MCP_CLIENT": "vscode",
        "REA_MCP_TOOLSET": "core"
      }
    }
  }
}
```

### Codex CLI

```toml
[mcp_servers.rea]
command = "rea-mcp"
args = ["mcp", "--toolset", "core"]

[mcp_servers.rea.env]
REA_MCP_CLIENT = "codex"
REA_MCP_TOOLSET = "core"
```

### Gemini CLI

```json
{
  "mcpServers": {
    "rea": {
      "command": "rea-mcp",
      "args": ["mcp", "--toolset", "core"],
      "env": {
        "REA_MCP_CLIENT": "generic",
        "REA_MCP_TOOLSET": "core"
      }
    }
  }
}
```

### Verify any client

```bash
rea doctor                         # provider/tool readiness
rea mcp --toolset core             # confirm the server starts
rea mcp --toolset core --available-only
rea manifest                      # compact command list for skill/CLI use
```

Restart the client after changing its config. If the client shows the server but
no tools, check that the command resolves on `PATH` (`rea-mcp`, `rea`, or
`python -m rea_mcp`). On Windows, prefer the installed `rea-mcp` entry point and
quote paths containing spaces.

### AACode

[AACode](https://github.com/kandada/aacode) is a lightweight Python/DeepSeek ReAct
CLI coding agent. Its system prompt already points reverse-engineering tasks at
`rea-python` (`pip install rea-mcp`), so no separate MCP registration is needed:
AACode can call the CLI through its shell tool.

```bash
pip install rea-mcp          # install once in the environment AACode uses
rea doctor                   # confirm providers
```

Then give AACode a task such as:

```text
Analyze /path/to/app.apk with rea-python. Start with `rea triage`, keep the
evidence IDs, follow next_probes only when needed, and report limitations.
```

CLI-first is a good fit for AACode because its shell/Python execution model avoids
advertising the full MCP catalog. Keep `rea` on `PATH` inside any sandbox or
container AACode uses; if the target is on the host, make it visible to that
environment first.

## Response budgets

MCP results are capped at 512 KiB by default (`REA_MCP_MAX_RESPONSE_BYTES`). Oversized analysis results are retained as Evidence and returned as a compact summary with an `evidence_reference`; use `evidence-export`, `inspect-analysis-view --view record --evidence-id <id>`, or `get-evidence-bundle --full` for the complete data. Set a CLI budget with `--output-budget <bytes>`, select fields with `--filter-output 'evidence_id,normalized_result.format'`, or print only its token count with `--token-count`; an oversized CLI result is written to a UTF-8 JSON file and stdout receives a summary plus `output_path`. `inspect-analysis-view`, `inspect-artifact`, `inspect-managed-members`, `inspect-network-capture`, `inspect-android-package`, `inspect-android-class`, `inspect-android-method`, `decompile-android-apk`, `decompile-android-class`, and `analyze-javascript-application` page with `--offset`/`--limit` (JavaScript also has `--module-offset`/`--edge-offset`). Decompilers return a summary-sized preview by default; `--max-bytes` changes the limit and the full text remains in Evidence. `batch-decompile` caps pseudocode at 64 KiB per function (`--max-bytes-per-function 0` disables the cap). Captured web response bodies are capped at 32 KiB each and 512 KiB total; `observe-web-execution --bodies --retain-bodies` keeps the complete bodies in Evidence (up to 8 MiB) while returning bounded previews.

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
