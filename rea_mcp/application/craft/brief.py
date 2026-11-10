"""Human- and agent-readable brief for one craft project."""

from __future__ import annotations

from typing import Any


def build_brief(
    *,
    name: str,
    request: str,
    target: dict[str, Any],
    mode: str,
    stack: str,
    capture: dict[str, Any] | None = None,
    failures: list[str] | None = None,
    reference_files: list[str] | None = None,
) -> str:
    lines = [
        f"# {name}",
        "",
        "## Request",
        "",
        request.strip() or "(no request text)",
        "",
        "## Target",
        "",
        f"- kind: `{target.get('kind')}`",
    ]
    for key, value in target.items():
        if key != "kind" and value:
            lines.append(f"- {key}: `{value}`")
    lines.extend(
        [
            "",
            "## Mode",
            "",
            f"- {mode}",
        ]
    )
    if mode == "clean_room":
        lines.extend(
            [
                "",
                "Clean room: do not read the original target's code, files or page source.",
                "Use only the capture/ and reference/ material in this project.",
            ]
        )
    if stack:
        lines.extend(["", "## Stack", "", stack])
    if capture:
        lines.extend(["", "## Capture", ""])
        shots = capture.get("screenshots") or []
        if shots:
            lines.append("Screenshots:")
            lines.extend(f"- `{item}`" for item in shots)
        pages = capture.get("pages") or {}
        if isinstance(pages, dict):
            for width, page in pages.items():
                if not isinstance(page, dict):
                    continue
                lines.extend(
                    [
                        "",
                        f"### {width}px",
                        f"- title: {page.get('title') or ''}",
                        f"- scroll: {page.get('scrollWidth')} x {page.get('scrollHeight')}",
                        f"- headings: {', '.join(str(h.get('text')) for h in (page.get('headings') or [])[:12])}",
                        f"- colors: {', '.join(str(c) for c in (page.get('colors') or [])[:12])}",
                        f"- fonts: {', '.join(str(f) for f in (page.get('fonts') or [])[:6])}",
                    ]
                )
        if capture.get("url"):
            lines.append(f"- url: `{capture['url']}`")
    if reference_files:
        lines.extend(["", "## Reference", ""])
        lines.extend(f"- `{item}`" for item in reference_files)
    if failures:
        lines.extend(["", "## What is still wrong", ""])
        lines.extend(f"- {item}" for item in failures)
    lines.extend(
        [
            "",
            "## Deliverable",
            "",
            "Write the new project into this project's `app/` folder.",
            "Keep the app runnable from that folder and include a build step when the stack needs one.",
            "Do not copy logos, photos, text or assets from the original unless the user confirmed they own them.",
            "",
        ]
    )
    return "\n".join(lines)


__all__ = ["build_brief"]
