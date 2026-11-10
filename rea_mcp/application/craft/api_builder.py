"""OpenAI-compatible API builder for text-only models such as DeepSeek Flash."""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from ...domain.analysis_error import AnalysisError, AnalysisInputError
from ...domain.project import ProjectUsage
from ...domain.result import Result, err, ok
from ..project_store import ProjectStore

_MAX_FILES = 80
_MAX_FILE_BYTES = 2_000_000
_MAX_TOTAL_BYTES = 12_000_000


def api_configured() -> bool:
    return bool(
        os.environ.get("LLM_API_KEY")
        and os.environ.get("LLM_API_URL")
        and os.environ.get("LLM_MODEL_NAME")
    )


def _endpoint() -> str:
    base = (os.environ.get("LLM_API_URL") or "").rstrip("/")
    if base.endswith("/chat/completions"):
        return base
    return base + "/chat/completions"


def _capture_text(store: ProjectStore) -> str:
    capture = store.read_json("capture/target.json")
    if not isinstance(capture, dict):
        return "No capture is available. Build from the request."
    lines = [f"Target URL: {capture.get('url') or 'local target'}"]
    pages = capture.get("pages")
    if isinstance(pages, dict):
        for width, page in pages.items():
            if not isinstance(page, dict):
                continue
            lines.extend(
                [
                    f"\nViewport {width}px:",
                    f"- title: {page.get('title') or ''}",
                    f"- scroll: {page.get('scrollWidth')} x {page.get('scrollHeight')}",
                    f"- headings: {', '.join(str(item.get('text')) for item in (page.get('headings') or [])[:20])}",
                    f"- text: {str(page.get('text') or '')[:6000]}",
                    f"- colors: {', '.join(str(item) for item in (page.get('colors') or [])[:20])}",
                    f"- fonts: {', '.join(str(item) for item in (page.get('fonts') or [])[:12])}",
                    f"- buttons: {', '.join(str(item) for item in (page.get('buttons') or [])[:20])}",
                ]
            )
    return "\n".join(lines)


def _system_prompt() -> str:
    return """You are a coding agent that rebuilds a user interface from text-only observations.
You cannot see images or screenshots. Use only the supplied text, layout and request.

Return exactly one JSON object, with no markdown and no prose:
{
  "files": {"relative/path.ext": "complete file contents", ...},
  "summary": "what you built"
}

Rules:
- Paths are relative to the app folder. Never use absolute paths or '..'.
- Include a runnable app. For a static site include index.html at the root.
- Do not copy logos, photos, text or assets unless the request says they are authorized.
- Prefer plain HTML/CSS/JS for a website clone; use the requested stack when given.
- Keep the output focused and complete; do not leave placeholders.
"""


def _request(payload: dict[str, Any]) -> Result[dict[str, Any], AnalysisError]:
    key = os.environ.get("LLM_API_KEY")
    if not key:
        return err(AnalysisInputError(operation="craft-build", message="LLM_API_KEY is not set"))
    request = urllib.request.Request(
        _endpoint(),
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as cause:
        detail = cause.read().decode("utf-8", errors="replace")[-2000:]
        return err(
            AnalysisInputError(
                operation="craft-build",
                message=f"LLM request failed ({cause.code}): {detail}",
            )
        )
    except (urllib.error.URLError, OSError, TimeoutError) as cause:
        return err(
            AnalysisInputError(operation="craft-build", message=f"LLM request failed: {cause}")
        )
    try:
        value = json.loads(body)
    except ValueError as cause:
        return err(
            AnalysisInputError(
                operation="craft-build", message=f"LLM returned invalid JSON: {cause}"
            )
        )
    if not isinstance(value, dict):
        return err(
            AnalysisInputError(operation="craft-build", message="LLM response is not an object")
        )
    return ok(value)


def _parse_content(content: str) -> dict[str, Any] | None:
    text = content.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1]
        if text.rstrip().endswith("```"):
            text = text.rstrip()[:-3]
    try:
        value = json.loads(text)
    except ValueError:
        start = text.find("{")
        if start < 0:
            return None
        try:
            value, _end = json.JSONDecoder().raw_decode(text[start:])
        except ValueError:
            return None
    return value if isinstance(value, dict) else None


def _safe_path(value: str) -> Path | None:
    path = Path(value)
    if path.is_absolute() or any(part in ("..", "") for part in path.parts):
        return None
    return path


def run_api_builder(
    store: ProjectStore,
    *,
    prompt: str,
    round_number: int = 1,
) -> Result[dict[str, Any], AnalysisError]:
    if not api_configured():
        return err(
            AnalysisInputError(
                operation="craft-build",
                message="set LLM_API_KEY, LLM_API_URL and LLM_MODEL_NAME for the API builder",
            )
        )
    capture = _capture_text(store)
    user = "\n\n".join(
        [
            prompt,
            "## Text-only capture",
            capture,
            "## Output",
            "Return the complete files as the JSON object described in the system message.",
        ]
    )
    payload: dict[str, Any] = {
        "model": os.environ.get("LLM_MODEL_NAME"),
        "messages": [
            {"role": "system", "content": _system_prompt()},
            {"role": "user", "content": user},
        ],
        "temperature": 0.2,
        "max_tokens": 12000,
    }
    started = time.monotonic()
    response = _request(payload)
    if not response.ok:
        return response
    choices = response.value.get("choices")
    if not isinstance(choices, list) or not choices:
        return err(AnalysisInputError(operation="craft-build", message="LLM returned no choices"))
    message = choices[0].get("message") if isinstance(choices[0], dict) else None
    content = message.get("content") if isinstance(message, dict) else None
    parsed = _parse_content(content if isinstance(content, str) else "")
    if parsed is None:
        return err(
            AnalysisInputError(operation="craft-build", message="LLM did not return the file JSON")
        )
    files = parsed.get("files")
    if not isinstance(files, dict) or not files:
        return err(AnalysisInputError(operation="craft-build", message="LLM returned no files"))
    if len(files) > _MAX_FILES:
        return err(
            AnalysisInputError(operation="craft-build", message="LLM returned too many files")
        )
    total = 0
    safe_files: list[tuple[Path, str]] = []
    for relative, value in files.items():
        path = _safe_path(str(relative))
        if path is None or not isinstance(value, str):
            return err(
                AnalysisInputError(
                    operation="craft-build", message=f"unsafe or invalid output path: {relative}"
                )
            )
        encoded = value.encode("utf-8")
        if len(encoded) > _MAX_FILE_BYTES:
            return err(
                AnalysisInputError(
                    operation="craft-build", message=f"file is too large: {relative}"
                )
            )
        total += len(encoded)
        if total > _MAX_TOTAL_BYTES:
            return err(
                AnalysisInputError(operation="craft-build", message="LLM output is too large")
            )
        safe_files.append((path, value))
    for relative, value in safe_files:
        destination = store.app_dir / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(value, encoding="utf-8")
    elapsed = time.monotonic() - started
    usage = response.value.get("usage") if isinstance(response.value.get("usage"), dict) else {}
    tokens = int(usage.get("total_tokens") or 0) if isinstance(usage, dict) else 0
    store.write_json(
        f"builds/round-{round_number:04d}/builder.json",
        {
            "builder": "deepseek-api",
            "model": os.environ.get("LLM_MODEL_NAME"),
            "exit_code": 0,
            "output": str(parsed.get("summary") or "")[:2000],
            "seconds": round(elapsed, 3),
            "files": [str(path) for path, _ in safe_files],
        },
    )
    store.add_usage(ProjectUsage(turns=1, tokens=tokens, seconds=elapsed))
    store.journal(
        {
            "event": "build",
            "round": round_number,
            "builder": "deepseek-api",
            "files": len(safe_files),
        }
    )
    return ok(
        {
            "builder": "deepseek-api",
            "exit_code": 0,
            "seconds": round(elapsed, 3),
            "tokens": tokens,
            "files": [str(path) for path, _ in safe_files],
            "summary": str(parsed.get("summary") or ""),
        }
    )


__all__ = ["api_configured", "run_api_builder"]
