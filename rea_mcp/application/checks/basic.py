"""Build and website checks for the craft loop."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from ...domain.check import CheckResult, Claim
from ..craft.capture import capture_website, serve_directory, site_directory
from .environment import environment_check
from .runtime import runtime_check
from .runtime_ui import runtime_ui_check


def _run(command: list[str], cwd: Path, timeout: int = 300) -> tuple[bool, str]:
    try:
        process = subprocess.run(
            command,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "CI": "1"},
        )
    except (OSError, subprocess.TimeoutExpired) as cause:
        return False, f"could not run {command[0]}: {cause}"
    output = (process.stdout or "") + (process.stderr or "")
    return process.returncode == 0, output[-8000:]


def _unity() -> str | None:
    configured = os.environ.get("REA_UNITY")
    if configured:
        return configured
    for pattern in (
        "/Applications/Unity/Hub/Editor/*/Unity.app/Contents/MacOS/Unity",
        "/Applications/Unity/Unity.app/Contents/MacOS/Unity",
    ):
        matches = sorted(Path("/").glob(pattern.lstrip("/")))
        if matches:
            return str(matches[-1])
    return shutil.which("Unity")


def _unreal() -> str | None:
    configured = os.environ.get("REA_UNREAL")
    if configured:
        return configured
    for pattern in (
        "/Users/Shared/Epic Games/UE_*/Engine/Binaries/Mac/UnrealEditor",
        "/Applications/Epic Games/UE_*/Engine/Binaries/Mac/UnrealEditor",
    ):
        matches = sorted(Path("/").glob(pattern.lstrip("/")))
        if matches:
            return str(matches[-1])
    return shutil.which("UnrealEditor")


def _packaged_program(app: Path) -> Path | None:
    build = app / "Build"
    if not build.is_dir():
        return None
    for candidate in sorted(build.rglob("*")):
        if candidate.is_file() and (
            candidate.suffix.lower() in (".exe", ".app", ".x86_64")
            or candidate.name.endswith(".app")
        ):
            return candidate
    return None


def _godot() -> str | None:
    configured = os.environ.get("REA_GODOT")
    if configured:
        return configured
    root = Path(__file__).resolve().parents[4] / "vendor/tools/godot"
    for candidate in (
        root / "Godot.app/Contents/MacOS/Godot",
        root / "Godot_v4.7.2-stable_mono_macos.universal/Godot.app/Contents/MacOS/Godot",
    ):
        if candidate.is_file():
            return str(candidate)
    return shutil.which("godot") or shutil.which("godot4")


def _npm() -> str | None:
    return shutil.which("npm") or shutil.which("npm.cmd")


def build_project(app_dir: str | Path) -> CheckResult:
    app = Path(app_dir).expanduser()
    if not app.is_dir():
        return CheckResult("build", 0, False, "app/ is missing")
    if (app / "package.json").is_file():
        try:
            package = json.loads((app / "package.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as cause:
            return CheckResult("build", 0, False, f"package.json is unreadable: {cause}")
        scripts = package.get("scripts") if isinstance(package, dict) else {}
        if isinstance(scripts, dict) and "build" in scripts:
            npm = _npm()
            if npm is None:
                return CheckResult("build", 0, False, "npm is not on PATH")
            passed, output = _run([npm, "run", "build"], app, 600)
            return CheckResult(
                "build",
                0,
                passed,
                "npm run build passed" if passed else f"npm run build failed: {output[-2000:]}",
            )
        return CheckResult("build", 0, True, "package.json has no build script")
    if (app / "Cargo.toml").is_file():
        cargo = shutil.which("cargo")
        if cargo is None:
            return CheckResult("build", 0, False, "cargo is not on PATH")
        passed, output = _run([cargo, "build", "--quiet"], app, 600)
        return CheckResult(
            "build",
            0,
            passed,
            "cargo build passed" if passed else f"cargo build failed: {output[-2000:]}",
        )
    if (app / "Assets").is_dir() and (app / "ProjectSettings").is_dir():
        editor = _unity()
        if editor is None:
            return CheckResult(
                "build",
                0,
                False,
                "Unity project found; set REA_UNITY or install Unity Hub/Editor",
                unknowns=["Unity editor"],
            )
        log = app / "Logs/build.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        passed, output = _run(
            [
                editor,
                "-batchmode",
                "-quit",
                "-nographics",
                "-projectPath",
                str(app),
                "-executeMethod",
                "CraftBuild.Build",
                "-logFile",
                str(log),
            ],
            app,
            1200,
        )
        packaged = _packaged_program(app)
        return CheckResult(
            "build",
            0,
            passed and packaged is not None,
            "Unity BuildPlayer completed"
            if passed and packaged
            else f"Unity build failed: {output[-2000:]}",
            artifacts=[str(packaged)] if packaged else [],
        )
    uprojects = list(app.glob("*.uproject"))
    if uprojects:
        editor = _unreal()
        if editor is None:
            return CheckResult(
                "build",
                0,
                False,
                "Unreal project found; set REA_UNREAL or install Unreal Engine",
                unknowns=["Unreal Engine"],
            )
        root = Path(editor).parents[4] if len(Path(editor).parents) > 4 else None
        uat = root / "Engine/Build/BatchFiles/RunUAT.sh" if root is not None else None
        if uat is None or not uat.is_file():
            return CheckResult(
                "build",
                0,
                False,
                "Unreal RunUAT was not found next to REA_UNREAL",
                unknowns=["RunUAT"],
            )
        platform = "Mac" if sys.platform == "darwin" else "Linux"
        passed, output = _run(
            [
                str(uat),
                "BuildCookRun",
                f"-project={uprojects[0]}",
                f"-platform={platform}",
                "-clientconfig=Development",
                "-build",
                "-cook",
                "-stage",
                "-pak",
                "-archive",
                f"-archivedirectory={app / 'Build'}",
                "-unattended",
                "-utf8output",
                "-nop4",
            ],
            app,
            2400,
        )
        packaged = _packaged_program(app)
        return CheckResult(
            "build",
            0,
            passed and packaged is not None,
            "Unreal BuildCookRun completed"
            if passed and packaged
            else f"Unreal build failed: {output[-2000:]}",
            artifacts=[str(packaged)] if packaged else [],
        )
    if (app / "project.godot").is_file():
        godot = _godot()
        if godot is None:
            return CheckResult(
                "build",
                0,
                False,
                "Godot project found; the Godot executable is not on PATH",
                unknowns=["Godot executable"],
            )
        passed, output = _run([godot, "--headless", "--path", str(app), "--import"], app, 300)
        return CheckResult(
            "build",
            0,
            passed,
            "Godot import passed" if passed else f"Godot import failed: {output[-2000:]}",
        )
    if list(app.glob("*.uproject")) or (
        (app / "Assets").is_dir() and (app / "ProjectSettings").is_dir()
    ):
        return CheckResult(
            "build",
            0,
            False,
            "game engine project detected; use the engine's own build adapter",
            unknowns=["external game engine build adapter"],
        )
    if (app / "pyproject.toml").is_file() or (app / "requirements.txt").is_file():
        python = shutil.which("python3") or shutil.which("python")
        if python is None:
            return CheckResult("build", 0, False, "python is not on PATH")
        passed, output = _run([python, "-m", "compileall", "-q", "."], app, 300)
        return CheckResult(
            "build",
            0,
            passed,
            "python compile passed" if passed else f"python compile failed: {output[-2000:]}",
        )
    if (app / "index.html").is_file():
        return CheckResult("build", 0, True, "static site; no build step")
    return CheckResult("build", 0, False, "no known project files in app/")


def _image_similarity(left: Path, right: Path) -> tuple[float | None, str | None]:
    try:
        from PIL import Image, ImageChops, ImageStat
    except Exception as cause:
        return None, f"Pillow is unavailable: {cause}"
    try:
        with Image.open(left) as a_file, Image.open(right) as b_file:
            a_image = a_file.convert("RGB").resize((96, 96))
            b_image = b_file.convert("RGB").resize((96, 96))
            diff = ImageChops.difference(a_image, b_image)
            stat = ImageStat.Stat(diff)
            mae = sum(stat.mean) / 3.0
            return max(0.0, min(100.0, 100.0 * (1.0 - mae / 255.0))), None
    except Exception as cause:
        return None, f"image comparison failed: {cause}"


def _text_set(value: Any) -> set[str]:
    return {token.lower() for token in str(value or "").split() if len(token) > 2}


def _layout_similarity(a: dict[str, Any], b: dict[str, Any]) -> float:
    if not a or not b:
        return 0.0
    scores: list[float] = []
    for key in ("scrollWidth", "scrollHeight"):
        av = float(a.get(key) or 0)
        bv = float(b.get(key) or 0)
        if av or bv:
            scores.append(100.0 - min(100.0, abs(av - bv) / max(av, bv, 1.0) * 100.0))
    at, bt = _text_set(a.get("text")), _text_set(b.get("text"))
    if at or bt:
        scores.append(100.0 * len(at & bt) / max(1, len(at | bt)))
    ah = {str(item.get("text", "")).lower() for item in a.get("headings") or []}
    bh = {str(item.get("text", "")).lower() for item in b.get("headings") or []}
    if ah or bh:
        scores.append(100.0 * len(ah & bh) / max(1, len(ah | bh)))
    ac = set(a.get("colors") or [])
    bc = set(b.get("colors") or [])
    if ac or bc:
        scores.append(100.0 * len(ac & bc) / max(1, len(ac | bc)))
    return round(sum(scores) / len(scores), 1) if scores else 0.0


def _page_capture(capture: dict[str, Any], width: int) -> tuple[dict[str, Any], Path | None]:
    pages = capture.get("pages") if isinstance(capture.get("pages"), dict) else {}
    page = pages.get(str(width)) if isinstance(pages, dict) else None
    shots = capture.get("screenshots")
    screenshots = [Path(str(item)) for item in shots] if isinstance(shots, list) else []
    path: Path | None = None
    # Screenshots are in the same width order as capture['widths'].
    widths = capture.get("widths")
    if isinstance(widths, list):
        for index, item in enumerate(widths):
            if int(item) == width and index < len(screenshots):
                path = screenshots[index]
                break
    return (page if isinstance(page, dict) else {}), path


def visual_check(
    original: dict[str, Any],
    built: dict[str, Any],
    *,
    round_number: int,
    good_enough: float,
) -> CheckResult:
    widths = [int(item) for item in original.get("widths") or []]
    claims: list[Claim] = []
    scores: list[float] = []
    artifacts: list[str] = []
    unknowns: list[str] = []
    notes: list[str] = []
    for width in widths:
        original_page, original_shot = _page_capture(original, width)
        built_page, built_shot = _page_capture(built, width)
        if original_shot is None or built_shot is None:
            unknowns.append(f"{width}px screenshots are missing")
            continue
        artifacts.extend([str(original_shot), str(built_shot)])
        image, error = _image_similarity(original_shot, built_shot)
        if image is None:
            unknowns.append(f"{width}px image comparison unavailable: {error}")
            continue
        layout = _layout_similarity(original_page, built_page)
        score = round(image * 0.7 + layout * 0.3, 1)
        scores.append(score)
        page_width = int(built_page.get("scrollWidth") or 0)
        no_scroll = page_width <= width + 2
        claims.append(
            Claim(f"{width}px resembles the original", score >= good_enough, f"{score:.1f}%")
        )
        claims.append(
            Claim(f"{width}px does not scroll sideways", no_scroll, f"scrollWidth={page_width}")
        )
        notes.append(f"{width}px {score:.1f}%")
    if not scores:
        return CheckResult(
            "web-visual",
            round_number,
            False,
            "the build could not be compared",
            unknowns=unknowns or ["no comparable screenshots"],
            artifacts=artifacts,
            good_enough=good_enough,
        )
    similarity = round(sum(scores) / len(scores), 1)
    passed = bool(claims) and all(claim.passed for claim in claims) and not unknowns
    return CheckResult(
        "web-visual",
        round_number,
        passed,
        "; ".join(notes),
        similarity=similarity,
        good_enough=good_enough,
        claims=claims,
        unknowns=unknowns,
        artifacts=artifacts,
    )


def website_check(
    store: Any,
    round_number: int,
    *,
    good_enough: float = 85.0,
) -> CheckResult:
    original = store.read_json("capture/target.json")
    if not isinstance(original, dict) or not isinstance(original.get("pages"), dict):
        return CheckResult(
            "web-visual",
            round_number,
            False,
            "study capture is missing",
            unknowns=["capture/target.json"],
        )
    site = site_directory(store.app_dir)
    if site is None:
        return CheckResult(
            "web-visual",
            round_number,
            False,
            "no built website found in app/",
            unknowns=["built site"],
        )
    output = store.round_dir(round_number) / "capture"
    try:
        with serve_directory(site) as url:
            captured = capture_website(
                url,
                output,
                widths=[int(item) for item in original.get("widths") or []],
            )
    except Exception as cause:
        return CheckResult(
            "web-visual",
            round_number,
            False,
            f"built site capture failed: {cause}",
            unknowns=["built capture"],
        )
    if not captured.ok:
        return CheckResult(
            "web-visual",
            round_number,
            False,
            f"built site capture failed: {captured.error.message}",
            unknowns=["built capture"],
        )
    return visual_check(
        original, captured.value, round_number=round_number, good_enough=good_enough
    )


def game_self_test(store: Any, round_number: int) -> CheckResult:
    app = store.app_dir
    report = app / "self-test.json"
    if not report.is_file():
        return CheckResult(
            "game-self-test",
            round_number,
            False,
            "app/self-test.json is missing",
            unknowns=["self-test report"],
        )
    try:
        payload = json.loads(report.read_text(encoding="utf-8"))
    except (OSError, ValueError) as cause:
        return CheckResult(
            "game-self-test", round_number, False, f"self-test is unreadable: {cause}"
        )
    steps = payload.get("steps") if isinstance(payload, dict) else None
    if not isinstance(steps, list) or not steps:
        return CheckResult("game-self-test", round_number, False, "self-test has no steps")
    claims = [
        Claim(
            str(step.get("step") or "step"), bool(step.get("passed")), str(step.get("detail") or "")
        )
        for step in steps
        if isinstance(step, dict)
    ]
    return CheckResult(
        "game-self-test",
        round_number,
        bool(claims) and all(claim.passed for claim in claims),
        f"{sum(1 for claim in claims if claim.passed)} of {len(claims)} steps passed",
        claims=claims,
        artifacts=[str(report)],
    )


def run_checks(store: Any, round_number: int, *, good_enough: float = 85.0) -> list[CheckResult]:
    target = store.manifest.target or {}
    kind = str(target.get("kind") or "")
    if kind == "environment":
        return [environment_check(store, round_number)]
    build = build_project(store.app_dir)
    build.round = round_number
    results = [build]
    if not build.passed:
        return results
    if kind == "website":
        results.append(website_check(store, round_number, good_enough=good_enough))
    if kind == "game":
        results.append(game_self_test(store, round_number))
    runtime_manifest = store.app_dir / "runtime.json"
    if runtime_manifest.is_file():
        runtime = store.read_json("app/runtime.json")
        if isinstance(runtime, dict) and runtime.get("window_title") is not None:
            results.append(runtime_ui_check(store, round_number))
        else:
            results.append(runtime_check(store, round_number))
    from ..plugins import run_plugin_checks, run_wasm_checks

    results.extend(run_plugin_checks(store, round_number))
    results.extend(run_wasm_checks(store, round_number))
    return results


__all__ = [
    "build_project",
    "game_self_test",
    "run_checks",
    "visual_check",
    "website_check",
]
