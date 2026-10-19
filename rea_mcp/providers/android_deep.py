"""Deep Android analysis over the caller-supplied JADX CLI.

Decompiles an APK once per process and serves class/method/ reference queries
from the resulting Java sources. JADX is never installed by REA.
"""

from __future__ import annotations

import shlex
import tempfile
from pathlib import Path
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from ..process.supervision import run_owned_process
from .base import AnalysisExecution, CapabilityDescriptor, CapabilityEffects
from .engines import _CliEngine, _jadx_operation_timeout
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="android-deep", name="REA-Python Android deep", version="1")
_OPERATIONS = (
    "search_android_classes",
    "inspect_android_class",
    "inspect_android_method",
    "trace_android_references",
)
_CACHE: dict[tuple[str, str], Path] = {}


class AndroidDeepProvider(_CliEngine):
    provider_id = "android-deep"
    provider_name = "REA-Python Android deep (JADX)"
    tool_names = ("jadx",)
    env_var = "REA_JADX"
    effects = CapabilityEffects(launches_process=True)

    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return tuple(self._capability(operation) for operation in _OPERATIONS)

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format == "apk":
            return TargetSupport("supported")
        return TargetSupport("unsupported", reason="not an APK", code="target_format_unsupported")

    def analyze(self, operation, target, parameters, profile):  # type: ignore[no-untyped-def]
        del profile
        if operation not in _OPERATIONS:
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        available, _ = self._availability()
        if not available:
            return err(self._unavailable(operation))
        command = self._resolution().path
        assert command is not None
        decompiled = self._decompile(command, target.path, operation)
        if not decompiled.ok:
            return decompiled
        root = decompiled.value
        if operation == "search_android_classes":
            return self._search(root, parameters, operation)
        if operation == "inspect_android_class":
            return self._class(root, parameters, operation)
        if operation == "inspect_android_method":
            return self._method(root, parameters, operation)
        return self._references(root, parameters, operation)

    def _decompile(self, command: str, apk: str, operation: str) -> Result[Path, AnalysisError]:
        key = (command, apk)
        cached = _CACHE.get(key)
        if cached is not None and cached.exists():
            return ok(cached)
        root = Path(tempfile.mkdtemp(prefix="rea-jadx-deep-"))
        result = run_owned_process(
            [*shlex.split(command), "--no-res", "-d", str(root), apk],
            timeout=_jadx_operation_timeout(),
            operation=operation,
            max_output_bytes=512 * 1024,
        )
        if not result.ok:
            return err(result.error)
        _CACHE[key] = root
        return ok(root)

    def _search(self, root: Path, parameters: dict[str, Any], operation: str) -> Any:
        query, failure = _require(parameters, "query", operation)
        if failure is not None:
            return err(failure)
        needle = str(query).replace(".", "/").lower()
        limit = int(parameters.get("limit") or 200)
        matches = []
        for path in root.rglob("*.java"):
            relative = (
                path.relative_to(root / "sources").as_posix()
                if (root / "sources").exists()
                else path.relative_to(root).as_posix()
            )
            if needle in relative.lower():
                matches.append(
                    {"class": relative[: -len(".java")].replace("/", "."), "path": relative}
                )
            if len(matches) >= limit:
                break
        return ok(
            AnalysisExecution(
                result={"query": query, "matches": matches, "match_count": len(matches)},
                provider=self.identity(),
            )
        )

    def _class(self, root: Path, parameters: dict[str, Any], operation: str) -> Any:
        class_name, failure = _require(parameters, "class_name", operation)
        if failure is not None:
            return err(failure)
        found = _find_class(root, str(class_name))
        if found is None:
            return err(
                AnalysisInputError(operation=operation, message=f"class not found: {class_name}")
            )
        source = found.read_text(encoding="utf-8", errors="replace")
        return ok(
            AnalysisExecution(
                result={
                    "class": class_name,
                    "path": found.as_posix(),
                    "line_count": source.count("\n") + 1,
                    "source": source[:500_000],
                },
                provider=self.identity(),
            )
        )

    def _method(self, root: Path, parameters: dict[str, Any], operation: str) -> Any:
        class_name, failure = _require(parameters, "class_name", operation)
        if failure is not None:
            return err(failure)
        method, failure = _require(parameters, "method", operation)
        if failure is not None:
            return err(failure)
        found = _find_class(root, str(class_name))
        if found is None:
            return err(
                AnalysisInputError(operation=operation, message=f"class not found: {class_name}")
            )
        source = found.read_text(encoding="utf-8", errors="replace")
        snippet = _extract_method(source, str(method))
        if snippet is None:
            return err(
                AnalysisInputError(operation=operation, message=f"method not found: {method}")
            )
        return ok(
            AnalysisExecution(
                result={"class": class_name, "method": method, "snippet": snippet},
                provider=self.identity(),
            )
        )

    def _references(self, root: Path, parameters: dict[str, Any], operation: str) -> Any:
        query, failure = _require(parameters, "query", operation)
        if failure is not None:
            return err(failure)
        limit = int(parameters.get("limit") or 200)
        needle = str(query)
        matches: list[dict[str, Any]] = []
        for path in root.rglob("*.java"):
            text = path.read_text(encoding="utf-8", errors="replace")
            for number, line in enumerate(text.splitlines(), start=1):
                if needle in line:
                    matches.append(
                        {
                            "path": path.relative_to(root).as_posix(),
                            "line": number,
                            "text": line.strip()[:500],
                        }
                    )
                    if len(matches) >= limit:
                        break
            if len(matches) >= limit:
                break
        return ok(
            AnalysisExecution(
                result={"query": query, "matches": matches, "match_count": len(matches)},
                provider=self.identity(),
            )
        )


def _require(
    parameters: dict[str, Any], key: str, operation: str
) -> tuple[Any, AnalysisError | None]:
    value = parameters.get(key)
    if not value:
        return None, AnalysisInputError(operation=operation, message=f"{operation} requires {key}")
    return value, None


def _find_class(root: Path, class_name: str) -> Path | None:
    relative = class_name.replace(".", "/") + ".java"
    for path in root.rglob("*.java"):
        if path.as_posix().endswith("/" + relative) or path.name == Path(relative).name:
            return path
    return None


def _extract_method(source: str, method: str) -> str | None:
    needle = method + "("
    index = source.find(needle)
    if index < 0:
        return None
    brace = source.find("{", index)
    if brace < 0:
        return None
    depth = 0
    end = -1
    for position in range(brace, len(source)):
        char = source[position]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                end = position + 1
                break
    if end < 0:
        return None
    start = source.rfind("\n", 0, index) + 1
    return source[start:end][:200_000]


__all__ = ["AndroidDeepProvider"]
