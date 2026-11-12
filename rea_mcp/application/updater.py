"""Optional PyPI update check for the ``update`` command."""

from __future__ import annotations

import json
import re
import urllib.request
from typing import Any

_PACKAGE = "rea-mcp"
_PYPI_URL = f"https://pypi.org/pypi/{_PACKAGE}/json"


def _version_key(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", value))


def check_pypi(*, timeout: float = 5.0) -> dict[str, Any]:
    try:
        with urllib.request.urlopen(_PYPI_URL, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as cause:
        return {"check_error": str(cause)}
    latest = str((payload.get("info") or {}).get("version") or "")
    if not latest:
        return {"check_error": "PyPI response has no version"}
    return {
        "latest_version": latest,
        "release_url": f"https://pypi.org/project/{_PACKAGE}/{latest}/",
        "install_command": f"pip install -U {_PACKAGE}=={latest}",
    }


def update_report(current: str, *, check: bool) -> dict[str, Any]:
    report: dict[str, Any] = {
        "current_version": current,
        "channel": "pypi" if check else "source",
        "upgrade_available": False,
    }
    if not check:
        return report
    report.update(check_pypi())
    latest = str(report.get("latest_version") or "")
    if latest:
        report["upgrade_available"] = _version_key(latest) > _version_key(current)
    return report


__all__ = ["check_pypi", "update_report"]
