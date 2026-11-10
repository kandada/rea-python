"""Persistent project folder for analysis, checks, questions and build artifacts."""

from __future__ import annotations

import contextlib
import json
import os
import re
import tempfile
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

from ..domain.analysis_error import AnalysisInputError
from ..domain.check import CheckResult
from ..domain.evidence import Evidence, parse_evidence
from ..domain.project import ProjectManifest, ProjectUsage, now_ms, project_slug
from ..domain.result import Result, err, ok

_CHECK_NAME = re.compile(r"[^a-zA-Z0-9_.-]+")


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise


@contextlib.contextmanager
def _project_lock(root: Path) -> Iterator[None]:
    """A simple cross-process lock; best-effort on platforms without fcntl."""
    path = root / ".rea-project.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        try:
            try:
                import importlib

                fcntl = importlib.import_module("fcntl")
                flock = getattr(fcntl, "flock", None)
                lock_ex = getattr(fcntl, "LOCK_EX", None)
                if flock is not None and lock_ex is not None:
                    flock(handle.fileno(), lock_ex)
            except (ImportError, OSError):
                pass
            yield
        finally:
            with contextlib.suppress(OSError, ImportError):
                import importlib

                fcntl = importlib.import_module("fcntl")
                flock = getattr(fcntl, "flock", None)
                lock_un = getattr(fcntl, "LOCK_UN", None)
                if flock is not None and lock_un is not None:
                    flock(handle.fileno(), lock_un)


class ProjectStore:
    def __init__(self, root: str | Path, manifest: ProjectManifest) -> None:
        self.root = Path(root).expanduser().resolve()
        self.manifest = manifest

    @classmethod
    def create(
        cls,
        root: str | Path,
        manifest: ProjectManifest,
        *,
        overwrite: bool = False,
    ) -> Result[ProjectStore, AnalysisInputError]:
        path = Path(root).expanduser().resolve()
        if path.exists() and any(path.iterdir()) and not overwrite:
            return err(
                AnalysisInputError(
                    operation="project-create", message=f"project folder is not empty: {path}"
                )
            )
        try:
            for child in (
                "investigation/evidence",
                "investigation/unknowns",
                "investigation/findings",
                "investigation/hypotheses",
                "capture",
                "reference",
                "app",
                "checks",
                "inbox",
                "builds",
                "reports",
            ):
                (path / child).mkdir(parents=True, exist_ok=True)
            store = cls(path, manifest)
            store.save_manifest()
            store.write_text("investigation/brief.md", "")
            store.write_json("investigation/plan.json", {"steps": []})
            store.write_text("investigation/handoff.md", "")
            return ok(store)
        except OSError as cause:
            return err(AnalysisInputError(operation="project-create", message=str(cause)))

    @classmethod
    def open(cls, root: str | Path) -> Result[ProjectStore, AnalysisInputError]:
        path = Path(root).expanduser().resolve()
        manifest_path = path / "project.json"
        try:
            value = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest = ProjectManifest.from_dict(value)
        except (OSError, ValueError) as cause:
            return err(
                AnalysisInputError(
                    operation="project-open",
                    message=f"cannot read project manifest {manifest_path}: {cause}",
                )
            )
        return ok(cls(path, manifest))

    @property
    def project_id(self) -> str:
        return self.manifest.project_id

    @property
    def app_dir(self) -> Path:
        return self.root / "app"

    @property
    def capture_dir(self) -> Path:
        return self.root / "capture"

    @property
    def investigation_dir(self) -> Path:
        return self.root / "investigation"

    def _manifest_path(self) -> Path:
        return self.root / "project.json"

    def save_manifest(self) -> None:
        with _project_lock(self.root):
            _atomic_write(
                self._manifest_path(),
                json.dumps(self.manifest.to_dict(), indent=2, ensure_ascii=False).encode(),
            )

    def reload(self) -> None:
        loaded = json.loads(self._manifest_path().read_text(encoding="utf-8"))
        self.manifest = ProjectManifest.from_dict(loaded)

    def write_text(self, relative: str, text: str) -> Path:
        path = self.root / relative
        _atomic_write(path, text.encode("utf-8"))
        return path

    def read_text(self, relative: str) -> str | None:
        path = self.root / relative
        try:
            return path.read_text(encoding="utf-8")
        except OSError:
            return None

    def write_json(self, relative: str, value: Any) -> Path:
        path = self.root / relative
        _atomic_write(path, json.dumps(value, indent=2, ensure_ascii=False).encode("utf-8"))
        return path

    def read_json(self, relative: str) -> Any | None:
        text = self.read_text(relative)
        if text is None:
            return None
        try:
            return json.loads(text)
        except ValueError:
            return None

    # -- evidence ---------------------------------------------------------
    def evidence_path(self, evidence_id: str) -> Path:
        safe = evidence_id if re.fullmatch(r"ev_[a-f0-9]{64}", evidence_id) else "invalid"
        shard = safe[3:5] if safe.startswith("ev_") else "00"
        return self.investigation_dir / "evidence" / shard / f"{safe}.json"

    def add_evidence(self, evidence: Evidence) -> Path:
        path = self.evidence_path(evidence.evidence_id)
        _atomic_write(path, evidence.model_dump_json(indent=2).encode("utf-8"))
        return path

    def get_evidence(self, evidence_id: str) -> Evidence | None:
        path = self.evidence_path(evidence_id)
        try:
            parsed = parse_evidence(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            return None
        return parsed.value if parsed.ok else None

    def evidence_ids(self) -> list[str]:
        directory = self.investigation_dir / "evidence"
        return sorted(path.stem for path in directory.rglob("ev_*.json"))

    # -- unknowns/findings -------------------------------------------------
    def add_unknown(self, unknown: dict[str, Any]) -> Path:
        key = str(unknown.get("unknown_id") or unknown.get("id") or uuid.uuid4().hex)
        safe = re.sub(r"[^a-zA-Z0-9_.-]+", "_", key)
        return self.write_json(f"investigation/unknowns/{safe}.json", unknown)

    def list_unknowns(self) -> list[dict[str, Any]]:
        directory = self.investigation_dir / "unknowns"
        rows = []
        for path in sorted(directory.glob("*.json")):
            value = self.read_json(path.relative_to(self.root).as_posix())
            if isinstance(value, dict) and value.get("status") == "open":
                rows.append(value)
        return rows

    def add_finding(self, finding: dict[str, Any]) -> Path:
        key = str(finding.get("finding_id") or uuid.uuid4().hex[:16])
        return self.write_json(f"investigation/findings/{key}.json", finding)

    def list_findings(self) -> list[dict[str, Any]]:
        return [
            value
            for path in sorted((self.investigation_dir / "findings").glob("*.json"))
            if isinstance(value := self.read_json(path.relative_to(self.root).as_posix()), dict)
        ]

    def add_hypothesis(self, hypothesis: dict[str, Any]) -> Path:
        key = str(hypothesis.get("hypothesis_id") or uuid.uuid4().hex[:16])
        return self.write_json(f"investigation/hypotheses/{key}.json", hypothesis)

    def journal(self, event: dict[str, Any]) -> None:
        path = self.investigation_dir / "journal.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"at": now_ms(), **event}, ensure_ascii=False) + "\n")

    # -- checks ------------------------------------------------------------
    def save_check(self, result: CheckResult) -> Path:
        safe = _CHECK_NAME.sub("-", result.check).strip("-") or "check"
        directory = self.root / "checks" / f"round-{result.round:04d}"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{safe}.json"
        _atomic_write(path, json.dumps(result.to_dict(), indent=2).encode("utf-8"))
        self.manifest.checks.append(result.to_dict())
        self.manifest.touch()
        self.save_manifest()
        return path

    def checks(self, round_number: int | None = None) -> list[CheckResult]:
        base = self.root / "checks"
        rows: list[CheckResult] = []
        for path in sorted(base.glob("round-*/**/*.json")):
            if round_number is not None and path.parent.name != f"round-{round_number:04d}":
                continue
            value = self.read_json(path.relative_to(self.root).as_posix())
            if isinstance(value, dict):
                rows.append(CheckResult.from_dict(value))
        return rows

    def latest_checks(self) -> list[CheckResult]:
        rounds = [
            int(path.name.split("-")[-1])
            for path in (self.root / "checks").glob("round-*")
            if path.name.split("-")[-1].isdigit()
        ]
        return self.checks(max(rounds)) if rounds else []

    def next_round(self) -> int:
        rounds = [
            int(path.name.split("-")[-1])
            for path in (self.root / "checks").glob("round-*")
            if path.name.split("-")[-1].isdigit()
        ]
        return (max(rounds) if rounds else 0) + 1

    def round_dir(self, number: int) -> Path:
        path = self.root / "checks" / f"round-{number:04d}"
        path.mkdir(parents=True, exist_ok=True)
        return path

    # -- inbox/approvals ---------------------------------------------------
    def ask(self, question: str, *, options: list[str] | None = None) -> dict[str, Any]:
        item = {
            "id": "ask_" + uuid.uuid4().hex[:12],
            "kind": "question",
            "question": question,
            "options": options or [],
            "status": "open",
            "created_at": now_ms(),
        }
        self.write_json(f"inbox/open_{item['id']}.json", item)
        return item

    def ask_approval(self, action: str, detail: str = "") -> dict[str, Any]:
        item = {
            "id": "apr_" + uuid.uuid4().hex[:12],
            "kind": "approval",
            "action": action,
            "detail": detail,
            "status": "open",
            "created_at": now_ms(),
        }
        self.write_json(f"inbox/open_{item['id']}.json", item)
        return item

    def inbox(self) -> list[dict[str, Any]]:
        rows = []
        for path in sorted((self.root / "inbox").glob("*.json")):
            value = self.read_json(path.relative_to(self.root).as_posix())
            if isinstance(value, dict) and value.get("status") == "open":
                rows.append(value)
        return rows

    def answer(self, item_id: str, value: str) -> Result[dict[str, Any], AnalysisInputError]:
        path = self.root / "inbox" / f"open_{item_id}.json"
        item = self.read_json(path.relative_to(self.root).as_posix())
        if not isinstance(item, dict):
            return err(
                AnalysisInputError(
                    operation="project-answer", message=f"unknown inbox item: {item_id}"
                )
            )
        item["status"] = "answered"
        item["answer"] = value
        item["answered_at"] = now_ms()
        self.write_json(f"inbox/answered_{item_id}.json", item)
        with contextlib.suppress(OSError):
            path.unlink()
        return ok(item)

    def finish(self, note: str = "user accepted the current result") -> dict[str, Any]:
        self.manifest.touch(status="ready", step="done")
        self.manifest.note = note
        self.save_manifest()
        self.journal({"event": "finish", "note": note})
        return self.summary()

    def pin(self, name: str | None = None) -> dict[str, Any]:
        import shutil
        import uuid as _uuid

        pin_id = (name or f"pin-{_uuid.uuid4().hex[:8]}").strip() or "pin"
        safe = re.sub(r"[^a-zA-Z0-9_.-]+", "-", pin_id).strip("-") or "pin"
        directory = self.root / "pins" / safe
        if directory.exists():
            raise FileExistsError(f"pin already exists: {safe}")
        directory.mkdir(parents=True)
        if self.app_dir.is_dir():
            shutil.copytree(
                self.app_dir,
                directory / "app",
                ignore=shutil.ignore_patterns(
                    "node_modules", "target", ".git", ".venv", "__pycache__", "dist", "build"
                ),
            )
        self.write_json(
            f"pins/{safe}/pin.json",
            {
                "id": safe,
                "name": safe,
                "created_at": now_ms(),
                "status": self.manifest.status,
                "mode": self.manifest.mode,
                "checks": self.manifest.checks[-20:],
            },
        )
        return {"id": safe, "path": str(directory), "app": str(directory / "app")}

    def list_pins(self) -> list[dict[str, Any]]:
        directory = self.root / "pins"
        rows = []
        for path in sorted(directory.glob("*/pin.json")):
            value = self.read_json(path.relative_to(self.root).as_posix())
            if isinstance(value, dict):
                value["path"] = str(path.parent)
                rows.append(value)
        return rows

    def delete_pin(self, pin_id: str) -> bool:
        directory = self.root / "pins" / re.sub(r"[^a-zA-Z0-9_.-]+", "-", pin_id)
        if directory.is_dir():
            import shutil

            shutil.rmtree(directory)
            return True
        return False

    def duplicate(self, destination: str | Path, name: str | None = None) -> dict[str, Any]:
        import shutil

        target = Path(destination).expanduser().resolve()
        if target.exists() and any(target.iterdir()):
            raise FileExistsError(f"duplicate destination is not empty: {target}")
        shutil.copytree(
            self.root,
            target,
            ignore=shutil.ignore_patterns(
                "node_modules",
                "target",
                ".git",
                ".venv",
                "__pycache__",
                "dist",
                "build",
                ".rea-project.lock",
            ),
            dirs_exist_ok=False,
        )
        loaded = ProjectStore.open(target)
        if loaded.ok:
            loaded.value.manifest.project_id = "prj_" + __import__("uuid").uuid4().hex[:20]
            loaded.value.manifest.name = name or f"{loaded.value.manifest.name} copy"
            loaded.value.manifest.agent_session = None
            loaded.value.manifest.touch()
            loaded.value.save_manifest()
        return {"path": str(target), "name": loaded.value.manifest.name if loaded.ok else name}

    def set_approval(self, kind: str, value: str) -> None:
        allowed = {
            "web",
            "commands",
            "outside_files",
            "publish",
            "delete_outside",
            "system",
            "other_tools",
        }
        if kind in allowed and value in ("allow", "ask", "refuse"):
            self.manifest.approvals[kind] = value  # type: ignore[assignment]
            self.manifest.touch()
            self.save_manifest()

    # -- usage/report ------------------------------------------------------
    def add_usage(self, usage: ProjectUsage) -> None:
        self.manifest.usage.add(usage)
        self.manifest.touch()
        self.save_manifest()
        self.write_json("builds/usage.json", self.manifest.usage.to_dict())

    def summary(self) -> dict[str, Any]:
        return {
            **self.manifest.to_dict(),
            "root": str(self.root),
            "app": str(self.app_dir),
            "capture": str(self.capture_dir),
            "evidence_count": len(self.evidence_ids()),
            "unknown_count": len(
                [u for u in self.list_unknowns() if u.get("status") != "resolved"]
            ),
            "latest_checks": [item.to_dict() for item in self.latest_checks()],
            "inbox": self.inbox(),
        }


def create_project(
    root: str | Path,
    *,
    name: str,
    request: str,
    target: str | None = None,
    mode: str = "clean_room",
    stack: str = "",
    builder: str = "",
) -> Result[ProjectStore, AnalysisInputError]:
    from ..domain.project import new_manifest

    manifest = new_manifest(
        name=name or project_slug(Path(root).name),
        request=request,
        target_path=target,
        mode=cast("Any", mode if mode in ("clean_room", "deep") else "clean_room"),
        stack=stack,
        builder=builder,
    )
    if target:
        candidate = Path(target).expanduser()
        if (
            candidate.is_dir()
            and (candidate / "manifest.json").is_file()
            and (candidate / "evidence.json").is_file()
        ):
            manifest.target = {"kind": "environment", "path": str(candidate)}
    return ProjectStore.create(root, manifest)


__all__ = ["ProjectStore", "create_project"]
