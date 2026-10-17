# Third-party notices

rea-mcp is an independent, unofficial Python port. It is **not affiliated with or endorsed by** the original REA project or any tool vendor. This document lists material third-party components, external tools, and reference projects, and the licenses they are commonly distributed under. It is informational and not exhaustive; the upstream license text and the terms of the copy you hold always govern.

## Reference project

- **morluto/rea** — https://github.com/morluto/rea — original TypeScript implementation whose architecture and concepts rea-mcp follows (MIT). No REA source code is bundled here; only independently written Python reimplements the same ideas.

## Python runtime dependencies

| Package | License | Role |
|---|---|---|
| pydantic | MIT | Schema validation |
| pydantic-settings | MIT | Environment configuration |
| typer | MIT | CLI framework |
| mcp | MIT | Model Context Protocol SDK (server/client) |

## Python development dependencies

| Package | License |
|---|---|
| pytest | MIT |
| pytest-asyncio | Apache-2.0 |
| pytest-cov | MIT |
| hypothesis | MPL-2.0 |
| mypy | MIT |
| ruff | MIT |

## External engines (caller-supplied; not bundled or installed)

rea-mcp only launches these when you provide them. Licenses below are the ones commonly reported by their upstream projects; confirm with the version you use.

| Tool | License (typical) | Used for |
|---|---|---|
| Ghidra | Apache-2.0 | Deep native analysis (via pyhidra) |
| Rizin / radare2 | LGPL-3.0 | Native analysis (via rzpipe) |
| GNU binutils objdump | GPL-3.0 | Native headers/disassembly |
| WABT | Apache-2.0 | WASM validation / WAT |
| evmole | MIT | EVM interface inference |
| mitmproxy | MIT | Live HTTP(S) capture |
| Wireshark tshark/capinfos | GPL-2.0 | pcap analysis |
| Binwalk | MIT | Firmware regions |
| Frida | wxWindows / LGPL-2.1 | Instrumentation |
| playwright | Apache-2.0 | Browser observation |
| pwntools / pwndbg | MIT | ELF / recorded crashes |
| adb (Android platform-tools) | Apache-2.0 | Android devices |
| Hopper | Proprietary | Native analysis (bring your own) |
| IDA Pro / Hex-Rays | Proprietary | Native analysis (bring your own) |
| JEB | Proprietary | Mobile / native analysis (bring your own) |

You must legally obtain and be authorized to use commercial tools under their own licenses. rea-mcp grants no tool license, key, or activation entitlement. See [DISCLAIMER.md](DISCLAIMER.md) for responsible-use guidance.

## Projects rea-mcp was built with

Developed for the authors' Python-based AI agent products **aacode** and **fastclaw**.
