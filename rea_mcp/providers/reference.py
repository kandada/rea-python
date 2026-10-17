"""Built-in reference-source inventory provider (pure Python).

Inventories a local source tree: file paths, sizes, digests, and a language
breakdown. Honors default exclusions for common generated/dependency paths.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.digests import sha256_hex
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="reference", name="REA-Python reference source", version="1")

_EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".venv",
    "venv",
    ".mypy_cache",
    ".ruff_cache",
}
_LANGUAGE_BY_SUFFIX = {
    ".py": "Python",
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".jsx": "JavaScript",
    ".go": "Go",
    ".rs": "Rust",
    ".c": "C",
    ".h": "C",
    ".cc": "C++",
    ".cpp": "C++",
    ".hpp": "C++",
    ".java": "Java",
    ".kt": "Kotlin",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".swift": "Swift",
    ".m": "Objective-C",
    ".sh": "Shell",
    ".json": "JSON",
    ".xml": "XML",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".toml": "TOML",
    ".md": "Markdown",
}
_MAX_FILES = 5000
_MAX_DIGEST_BYTES = 8 * 1024 * 1024


class ReferenceSourceProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="import_reference_source",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=("Reads the supplied tree read-only; symlinks are not followed.",),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.kind == "directory" or target.format == "directory":
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported",
            reason="reference source import requires a directory",
            code="target_kind_unsupported",
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del profile
        if operation != "import_reference_source":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        root = Path(target.path)
        if not root.is_dir():
            return err(AnalysisInputError(operation=operation, message="Target is not a directory"))

        files: list[dict[str, Any]] = []
        languages: dict[str, int] = {}
        total_bytes = 0
        truncated = False
        for child in sorted(root.rglob("*")):
            if any(part in _EXCLUDED_DIRS for part in child.parts):
                continue
            if not child.is_file():
                continue
            if len(files) >= _MAX_FILES:
                truncated = True
                break
            size = child.stat().st_size
            total_bytes += size
            language = _LANGUAGE_BY_SUFFIX.get(child.suffix.lower(), "Other")
            languages[language] = languages.get(language, 0) + 1
            digest: str | None = None
            if size <= _MAX_DIGEST_BYTES:
                digest = sha256_hex(child.read_bytes())
            files.append(
                {
                    "path": child.relative_to(root).as_posix(),
                    "size": size,
                    "sha256": digest,
                    "language": language,
                }
            )

        return ok(
            AnalysisExecution(
                result={
                    "file_count": len(files),
                    "total_bytes": str(total_bytes),
                    "languages": languages,
                    "files": files,
                    "truncated": truncated,
                },
                provider=_PROVIDER,
                limitations=("Generated and dependency directories are excluded by default.",),
            )
        )


__all__ = ["ReferenceSourceProvider"]
