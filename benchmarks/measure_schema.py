#!/usr/bin/env python3
"""Measure REA MCP surface size and optional skill size.

Usage:
    python benchmarks/measure_schema.py
    python benchmarks/measure_schema.py --json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rea_mcp.composition.factories import create_binary_session
from rea_mcp.config.settings import AppConfig
from rea_mcp.server.app import build_mcp_server

TOOLSETS = ("core", "native", "web", "android", "managed", "evidence", "external", "full")


def _tokens(text: str) -> int:
    try:
        import tiktoken

        return len(tiktoken.get_encoding("cl100k_base").encode(text))
    except Exception:
        return max(1, len(text) // 4)


async def measure(toolset: str) -> dict[str, object]:
    config = AppConfig().model_copy(update={"mcp_toolset": toolset, "mcp_client": "minimal"})
    server = build_mcp_server(create_binary_session(config), config)
    tools = await server.list_tools()
    text = json.dumps(
        [tool.model_dump() for tool in tools], ensure_ascii=False, separators=(",", ":")
    )
    return {
        "toolset": toolset,
        "tools": len(tools),
        "schema_bytes": len(text.encode("utf-8")),
        "schema_tokens": _tokens(text),
    }


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    rows = [await measure(toolset) for toolset in TOOLSETS]
    skill = Path("rea_mcp/data/skill.md").read_text(encoding="utf-8")
    rows.append(
        {
            "toolset": "skill",
            "tools": 0,
            "schema_bytes": len(skill.encode("utf-8")),
            "schema_tokens": _tokens(skill),
        }
    )
    if args.json:
        print(json.dumps(rows, indent=2))
        return
    print(f"{'mode':10} {'tools':>6} {'bytes':>9} {'tokens':>8}")
    for row in rows:
        print(
            f"{row['toolset']:10} {row['tools']:6} {row['schema_bytes']:9} {row['schema_tokens']:8}"
        )


if __name__ == "__main__":
    asyncio.run(main())
