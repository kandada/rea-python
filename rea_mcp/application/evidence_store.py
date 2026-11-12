"""Persistent Evidence/unknown ledger for the one-shot CLI.

The MCP server keeps a ledger for the lifetime of one process. The CLI creates a
fresh session per command, so it needs an explicit sidecar file to make
``record-unknown`` and Evidence IDs useful across invocations.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.result import Result, err, ok
from .investigation import InvestigationRecords

_STORE_DIRECTORY = ".rea"
_STORE_FILE = "evidence.json"


def nearest_project(start: str | Path) -> Path | None:
    """Return the nearest ancestor containing ``project.json``."""

    path = Path(start).expanduser()
    try:
        path = path.resolve()
    except OSError:
        return None
    if path.is_file():
        path = path.parent
    for candidate in (path, *path.parents):
        if (candidate / "project.json").is_file():
            return candidate
    return None


def _project_from_environment() -> Path | None:
    value = os.environ.get("REA_PROJECT")
    if not value:
        return None
    path = Path(value).expanduser()
    return path.resolve() if path.exists() else path


@dataclass
class EvidenceStore:
    root: Path
    path: Path
    project: Path | None = None

    @property
    def source(self) -> str:
        if self.project is not None:
            return "project"
        if self.path.is_file():
            return "sidecar"
        return "missing"

    def load(self) -> Result[InvestigationRecords, AnalysisError]:
        records = InvestigationRecords()
        if not self.path.is_file():
            return ok(records)
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as cause:
            return err(
                AnalysisInputError(
                    operation="evidence-store",
                    message=f"Evidence store is unreadable: {self.path}: {cause}",
                )
            )
        imported = records.ledger.import_bundle(payload)
        if not imported.ok:
            return err(imported.error)
        return ok(records)

    def save(self, records: InvestigationRecords) -> Result[dict[str, Any], AnalysisError]:
        bundle = records.ledger.export_bundle().model_dump()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            handle, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
            try:
                with os.fdopen(handle, "w", encoding="utf-8") as stream:
                    json.dump(bundle, stream, ensure_ascii=False, indent=2)
                    stream.write("\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, self.path)
            except Exception:
                with contextlib.suppress(OSError):
                    os.unlink(temporary)
                raise
        except OSError as cause:
            return err(
                AnalysisInputError(
                    operation="evidence-store",
                    message=f"Could not write Evidence store {self.path}: {cause}",
                )
            )
        return ok(
            {
                "path": str(self.path),
                "project": None if self.project is None else str(self.project),
                "source": self.source,
                "record_count": len(bundle.get("records", [])),
                "unknown_count": len(bundle.get("unknowns", [])),
            }
        )


def discover_store(
    *,
    target: str | Path | None = None,
    project: str | Path | None = None,
    base: str | Path | None = None,
) -> EvidenceStore:
    """Choose a project root or sidecar directory for the ledger."""

    explicit = project or _project_from_environment()
    if explicit is not None:
        root = Path(explicit).expanduser()
        if not root.is_absolute():
            root = (Path.cwd() / root).resolve()
        elif root.is_file():
            root = root.parent.resolve()
        else:
            root = root.resolve()
    elif target is not None:
        candidate = Path(target).expanduser()
        start = candidate if candidate.is_dir() else candidate.parent
        root = nearest_project(start) or start.resolve()
    else:
        start = Path(base).expanduser() if base is not None else Path.cwd()
        root = nearest_project(start) or start.resolve()
    project_root = root if (root / "project.json").is_file() else None
    return EvidenceStore(
        root=root,
        path=root / _STORE_DIRECTORY / _STORE_FILE,
        project=project_root,
    )


__all__ = ["EvidenceStore", "discover_store", "nearest_project"]
