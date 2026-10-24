"""Portable agent-environment bundle planning and atomic-ish writing."""

from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ...domain.analysis_error import AnalysisInputError
from ...domain.result import Result, err, ok

BUNDLE_MCP_PORT = 18765
BUNDLE_TARBALL_NAME = "rea-agents.tgz"
BUNDLE_NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
WINDOWS_RESERVED_NAME = re.compile(r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])$")
BUNDLE_NAME_MAX_LENGTH = 64


@dataclass
class EnvironmentBundleFile:
    path: str
    content: str


@dataclass
class EnvironmentBundlePlan:
    name: str
    package_source: dict[str, Any]
    tool_count: int
    state: dict[str, Any]
    check: dict[str, Any] | None
    files: list[EnvironmentBundleFile] = field(default_factory=list)
    copies: dict[str, str | None] = field(default_factory=dict)


def _error(message: str, issue: str) -> AnalysisInputError:
    return AnalysisInputError(
        message=message,
        operation="environment-export",
        details={"issues": [{"path": ["name"], "reason": "invalid_format", "message": issue}]},
    )


def validate_bundle_name(name: str) -> Result[str, AnalysisInputError]:
    if not BUNDLE_NAME.fullmatch(name) or len(name) > BUNDLE_NAME_MAX_LENGTH:
        return err(
            _error(
                f"The bundle name {name!r} is not a portable kebab-case label.",
                "use lowercase letters, digits and single hyphens, at most 64 characters",
            )
        )
    if WINDOWS_RESERVED_NAME.fullmatch(name):
        return err(
            _error(
                f"The bundle name {name!r} is reserved by Windows.",
                "con, prn, aux, nul, com1-com9 and lpt1-lpt9 are reserved",
            )
        )
    return ok(name)


def bundle_dockerfile(package_source: dict[str, Any]) -> str:
    specifier = str(package_source.get("specifier") or "")
    if package_source.get("kind") == "tarball":
        install = (
            f"COPY {BUNDLE_TARBALL_NAME} /tmp/\n"
            f"RUN npm install -g --ignore-scripts --no-fund --no-audit /tmp/{BUNDLE_TARBALL_NAME} "
            f"&& rm /tmp/{BUNDLE_TARBALL_NAME}"
        )
    else:
        install = f"RUN npm install -g --ignore-scripts --no-fund --no-audit {specifier}"
    return "\n".join(
        [
            "FROM node:22-bookworm-slim",
            "ENV MCP_HOST=0.0.0.0",
            f"ENV MCP_PORT={BUNDLE_MCP_PORT}",
            "RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*",
            install,
            "COPY --chown=node:node manifest.json evidence.json /env/",
            "USER node",
            'CMD ["rea","environment-serve","/env/manifest.json","--evidence","/env/evidence.json"]',
            "",
        ]
    )


def _python_literal(value: Any) -> str:
    return "None" if value is None else json.dumps(value)


def bundle_verifier(plan: EnvironmentBundlePlan) -> str:
    check = plan.check or {}
    return "\n".join(
        [
            '"""Checks the environment through its MCP endpoint: tool count and one answered status."""',
            "import json",
            "from mcp import ClientSession",
            "from mcp.client.streamable_http import streamable_http_client",
            f"TOOL_COUNT = {plan.tool_count}",
            f"TOOL = {_python_literal(check.get('tool'))}",
            f"EXPECTED_STATUS = {_python_literal(check.get('status'))}",
            "",
            "def answered_status(result):",
            "    data = result.structuredContent",
            "    if data is None:",
            '        text = "".join(getattr(part, "text", "") for part in result.content)',
            "        data = json.loads(text) if text else {}",
            '    return data.get("status") if isinstance(data, dict) else None',
            "",
            "async def verify(mcp_url):",
            "    async with streamable_http_client(mcp_url) as (read, write, _):",
            "        async with ClientSession(read, write) as session:",
            "            await session.initialize()",
            "            listed = await session.list_tools()",
            "            result = await session.call_tool(TOOL, {}) if TOOL is not None else None",
            "    count = len(listed.tools)",
            "    passed = count == TOOL_COUNT",
            '    description = f"listed {count} tools, expected {TOOL_COUNT}"',
            "    if result is not None:",
            "        status = None if result.isError else answered_status(result)",
            "        passed = passed and not result.isError and status == EXPECTED_STATUS",
            '        description += f"; {TOOL} answered status {status!r}, expected {EXPECTED_STATUS!r}"',
            "    else:",
            '        description += "; no GET tool without path parameters answers without arguments"',
            '    print(f"serve: {description}")',
            '    return [{"id": "serve", "result": passed, "description": description}]',
            "",
        ]
    )


def bundle_smoke_task(name: str) -> str:
    return (
        json.dumps(
            [
                {"id": "env", "type": "deploy_env", "env_id": name, "sandbox_type": "local"},
                {
                    "id": "serve",
                    "type": "env_outcome_verifier",
                    "env_id": name,
                    "file_artifact_id": f"check_{name}",
                    "verifier_id": "serve",
                },
            ],
            indent=2,
        )
        + "\n"
    )


def plan_environment_bundle(
    source: dict[str, Any],
    *,
    name: str | None = None,
    package_source: dict[str, Any] | None = None,
    tool_count: int = 0,
    state: dict[str, Any] | None = None,
    check: dict[str, Any] | None = None,
) -> Result[EnvironmentBundlePlan, AnalysisInputError]:
    chosen = name or str(source.get("name") or "")
    valid = validate_bundle_name(chosen)
    if not valid.ok:
        return err(valid.error)
    package = package_source or {"kind": "registry", "specifier": "rea-agents"}
    plan = EnvironmentBundlePlan(
        name=chosen,
        package_source=package,
        tool_count=tool_count,
        state=state or {"served": False, "reason": "replay-only"},
        check=check,
        files=[],
        copies={},
    )
    env_folder = f"envs/{chosen}"
    plan.files = [
        EnvironmentBundleFile(
            "README.md",
            f"# {chosen}\n\nAn agent environment exported by REA.\n\n"
            f"Tools: {tool_count}\nState: {plan.state}\n",
        ),
        EnvironmentBundleFile(f"{env_folder}/env.toml", f'environment_name = "{chosen}"\n'),
        EnvironmentBundleFile(f"{env_folder}/Dockerfile", bundle_dockerfile(package)),
        EnvironmentBundleFile(f"artifacts/check_{chosen}/verify.py", bundle_verifier(plan)),
        EnvironmentBundleFile("tasks/smoke.json", bundle_smoke_task(chosen)),
    ]
    plan.copies = {
        "manifest": f"{env_folder}/manifest.json",
        "evidence": f"{env_folder}/evidence.json",
        "tarball": f"{env_folder}/{BUNDLE_TARBALL_NAME}"
        if package.get("kind") == "tarball"
        else None,
    }
    return ok(plan)


def write_environment_bundle(
    plan: EnvironmentBundlePlan,
    directory: str | Path,
    *,
    manifest_bytes: bytes,
    evidence_bytes: bytes,
    package_tarball: str | Path | None = None,
) -> Result[list[dict[str, Any]], AnalysisInputError]:
    root = Path(directory).expanduser()
    if root.exists() and any(root.iterdir()):
        return err(
            AnalysisInputError(
                message=f"destination is not empty: {root}",
                operation="environment-export",
            )
        )
    written: list[dict[str, Any]] = []
    try:
        root.mkdir(parents=True, exist_ok=True)
        for file in plan.files:
            destination = root / file.path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(file.content, encoding="utf-8")
            os.chmod(destination, 0o600)
            written.append({"path": file.path, "bytes": len(file.content.encode())})
        copies = {
            plan.copies["manifest"]: manifest_bytes,
            plan.copies["evidence"]: evidence_bytes,
        }
        if plan.copies.get("tarball") and package_tarball is not None:
            copies[plan.copies["tarball"]] = Path(package_tarball).read_bytes()
        for relative, payload in copies.items():
            destination = root / str(relative)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(payload)
            os.chmod(destination, 0o600)
            written.append({"path": str(relative), "bytes": len(payload)})
    except OSError as cause:
        shutil.rmtree(root, ignore_errors=True)
        return err(AnalysisInputError(message=str(cause), operation="environment-export"))
    return ok(written)


__all__ = [
    "EnvironmentBundleFile",
    "EnvironmentBundlePlan",
    "bundle_dockerfile",
    "bundle_smoke_task",
    "bundle_verifier",
    "plan_environment_bundle",
    "validate_bundle_name",
    "write_environment_bundle",
]
