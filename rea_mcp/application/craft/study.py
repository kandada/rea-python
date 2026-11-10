"""Study phase: capture the target and write the project brief."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ...composition.factories import create_binary_session
from ...config.settings import AppConfig
from ...domain.analysis_error import AnalysisError, AnalysisInputError
from ...domain.project import ProjectManifest
from ...domain.result import Result, err, ok
from ..project_store import ProjectStore
from ..triage import triage_target
from .brief import build_brief
from .capture import DEFAULT_WIDTHS, capture_website, url_from_target


def detect_game_engine(path: str | Path) -> dict[str, Any] | None:
    root = Path(path).expanduser()
    if not root.is_dir():
        return None
    if (root / "project.godot").is_file():
        return {"engine": "godot", "clue": "project.godot"}
    if list(root.glob("*.uproject")):
        return {"engine": "unreal", "clue": "*.uproject"}
    if (root / "UnityPlayer.dll").is_file() or (
        (root / "Assets").is_dir() and (root / "ProjectSettings").is_dir()
    ):
        return {"engine": "unity", "clue": "UnityPlayer.dll or Assets/ProjectSettings"}
    if (root / "GameAssembly.dll").is_file():
        return {"engine": "unity-il2cpp", "clue": "GameAssembly.dll"}
    return None


def _reference_files(store: ProjectStore) -> list[str]:
    directory = store.root / "reference"
    if not directory.is_dir():
        return []
    return [
        path.relative_to(store.root).as_posix()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    ]


def study_project(
    store: ProjectStore,
    *,
    widths: list[int] | None = None,
    deep: bool | None = None,
) -> Result[dict[str, Any], AnalysisError]:
    manifest: ProjectManifest = store.manifest
    mode_deep = manifest.mode == "deep" if deep is None else deep
    target = manifest.target or {}
    kind = str(target.get("kind") or "none")
    capture: dict[str, Any] | None = None
    manifest.touch(status="studying", step="study")
    store.save_manifest()
    try:
        if kind == "website":
            url = url_from_target(target)
            if not url:
                manifest.touch(status="failed", step="study")
                store.save_manifest()
                return err(
                    AnalysisInputError(operation="craft-study", message="website target has no URL")
                )
            captured = capture_website(
                url,
                store.capture_dir,
                widths=widths or DEFAULT_WIDTHS,
                deep=mode_deep,
            )
            if not captured.ok:
                manifest.touch(status="failed", step="study")
                store.save_manifest()
                return err(captured.error)
            capture = captured.value
            store.write_json("capture/target.json", capture)
        elif kind == "environment":
            source = Path(str(target.get("path") or ""))
            if not source.is_dir():
                manifest.touch(status="failed", step="study")
                store.save_manifest()
                return err(
                    AnalysisInputError(
                        operation="craft-study", message="environment folder is missing"
                    )
                )
            environment_capture = store.capture_dir / "environment"
            environment_capture.mkdir(parents=True, exist_ok=True)
            import shutil

            for name in ("manifest.json", "evidence.json"):
                shutil.copyfile(source / name, environment_capture / name)
            capture = {"kind": "environment", "path": str(source)}
            store.write_json("capture/target.json", capture)
        elif kind in ("local", "file"):
            path = str(target.get("path") or "")
            if not path or not Path(path).exists():
                manifest.touch(status="failed", step="study")
                store.save_manifest()
                return err(
                    AnalysisInputError(operation="craft-study", message="target path is missing")
                )
            if mode_deep:
                session = create_binary_session(AppConfig())
                probe = triage_target(session, path)
                if probe.ok:
                    capture = {"kind": "local", "triage": probe.value}
                else:
                    capture = {"kind": "local", "triage_error": probe.error.message}
            else:
                capture = {"kind": "local", "clean_room": True}
            engine = detect_game_engine(path) if mode_deep else None
            if engine is not None:
                capture["game_engine"] = engine
                manifest.target["kind"] = "game"
            store.write_json("capture/target.json", capture)
        else:
            capture = {"kind": "none"}
            store.write_json("capture/target.json", capture)
    except Exception as cause:
        manifest.touch(status="failed", step="study")
        store.save_manifest()
        return err(AnalysisInputError(operation="craft-study", message=str(cause)))
    brief = build_brief(
        name=manifest.name,
        request=manifest.request,
        target=target,
        mode=manifest.mode,
        stack=manifest.stack,
        capture=capture,
        reference_files=_reference_files(store),
    )
    store.write_text("investigation/brief.md", brief)
    manifest.touch(status="building", step="build")
    store.save_manifest()
    store.journal({"event": "study", "kind": kind, "mode": manifest.mode})
    return ok({"capture": capture, "brief": str(store.investigation_dir / "brief.md")})


__all__ = ["study_project"]
