"""Java class/JAR static inventory (pure Python)."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from ..domain.analysis_error import (
    AnalysisCapabilityUnavailableError,
    AnalysisError,
    AnalysisInputError,
)
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="java", name="REA-Python Java class/JAR", version="1")
_OPERATIONS = (
    "inspect_java_archive",
    "inspect_java_class",
    "search_java_classes",
    "decompile_java_class",
)
_ACCESS = {
    0x0001: "public",
    0x0010: "final",
    0x0020: "super",
    0x0200: "interface",
    0x0400: "abstract",
    0x1000: "synthetic",
    0x2000: "annotation",
    0x4000: "enum",
    0x8000: "module",
}


def _flags(value: int) -> list[str]:
    return [name for bit, name in _ACCESS.items() if value & bit]


def _u1(data: bytes, offset: int) -> tuple[int, int]:
    return data[offset], offset + 1


def _u2(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 2 > len(data):
        raise ValueError("truncated u2")
    return int.from_bytes(data[offset : offset + 2], "big"), offset + 2


def _u4(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 4 > len(data):
        raise ValueError("truncated u4")
    return int.from_bytes(data[offset : offset + 4], "big"), offset + 4


def _skip(data: bytes, offset: int, count: int) -> int:
    if offset + count > len(data):
        raise ValueError("truncated class file")
    return offset + count


def _parse_class(data: bytes) -> dict[str, Any]:
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        raise ValueError("not a Java class file")
    offset = 4
    minor, offset = _u2(data, offset)
    major, offset = _u2(data, offset)
    count, offset = _u2(data, offset)
    constants: list[Any] = [None] * count
    index = 1
    while index < count:
        tag, offset = _u1(data, offset)
        if tag == 1:
            length, offset = _u2(data, offset)
            constants[index] = data[offset : offset + length].decode("utf-8", errors="replace")
            offset += length
        elif tag in (3, 4):
            constants[index], offset = _u4(data, offset)
        elif tag in (5, 6):
            constants[index] = int.from_bytes(data[offset : offset + 8], "big", signed=True)
            offset += 8
            index += 1
        elif tag in (7, 8, 16, 19, 20):
            constants[index], offset = _u2(data, offset)
        elif tag in (9, 10, 11, 12, 17, 18):
            constants[index], offset = _u4(data, offset)
        elif tag == 15:
            constants[index] = (data[offset], data[offset + 1])
            offset = _skip(data, offset, 3)
        else:
            raise ValueError(f"unknown constant pool tag {tag}")
        index += 1

    def utf8(value: Any) -> str | None:
        if isinstance(value, int) and 0 < value < len(constants):
            item = constants[value]
            return item if isinstance(item, str) else None
        return None

    def class_name(value: Any) -> str | None:
        text = utf8(value) if isinstance(value, int) else None
        return text.replace("/", ".") if text else None

    access, offset = _u2(data, offset)
    this_class, offset = _u2(data, offset)
    super_class, offset = _u2(data, offset)
    interfaces_count, offset = _u2(data, offset)
    interfaces = []
    for _ in range(interfaces_count):
        item, offset = _u2(data, offset)
        interfaces.append(class_name(constants[item]) if item else None)

    def members(offset: int) -> tuple[list[dict[str, Any]], int]:
        total, offset = _u2(data, offset)
        rows = []
        for _ in range(total):
            member_access, offset = _u2(data, offset)
            name_index, offset = _u2(data, offset)
            descriptor_index, offset = _u2(data, offset)
            attributes_count, offset = _u2(data, offset)
            code_length = None
            for _ in range(attributes_count):
                attribute_name, offset = _u2(data, offset)
                length, offset = _u4(data, offset)
                if utf8(attribute_name) == "Code" and length >= 4:
                    code_length = int.from_bytes(data[offset + 4 : offset + 8], "big")
                offset = _skip(data, offset, length)
            rows.append(
                {
                    "access": member_access,
                    "flags": _flags(member_access),
                    "name": utf8(name_index),
                    "descriptor": utf8(descriptor_index),
                    "code_length": code_length,
                }
            )
        return rows, offset

    fields, offset = members(offset)
    methods, offset = members(offset)
    attributes_count, offset = _u2(data, offset)
    for _ in range(attributes_count):
        _name_index, offset = _u2(data, offset)
        length, offset = _u4(data, offset)
        offset = _skip(data, offset, length)
    return {
        "magic": "cafebabe",
        "major": major,
        "minor": minor,
        "constant_pool_count": count,
        "class": class_name(constants[this_class]) if this_class else None,
        "super": class_name(constants[super_class]) if super_class else None,
        "interfaces": interfaces,
        "access": access,
        "flags": _flags(access),
        "fields": fields,
        "methods": methods,
        "method_count": len(methods),
        "field_count": len(fields),
    }


def _classes_in_archive(path: Path) -> list[str]:
    with zipfile.ZipFile(path) as archive:
        return sorted(
            name
            for name in archive.namelist()
            if name.endswith(".class") and not name.endswith("/")
        )


def _vendor_root() -> Path:
    return Path(__file__).resolve().parents[3] / "vendor"


def _java() -> str | None:
    configured = os.environ.get("REA_JAVA")
    if configured:
        return configured
    candidate = _vendor_root() / "tools/jdk/Contents/Home/bin/java"
    if candidate.is_file():
        return str(candidate)
    return shutil.which("java")


def _vineflower() -> tuple[str, bool] | None:
    configured = os.environ.get("REA_VINEFLOWER")
    if configured:
        path = Path(configured).expanduser()
        return (str(path), path.suffix.lower() == ".jar")
    candidate = _vendor_root() / "tools/vineflower/vineflower-1.12.0.jar"
    if candidate.is_file():
        return (str(candidate), True)
    found = shutil.which("vineflower")
    return (found, False) if found else None


def _read_class(path: Path, class_name: str | None = None) -> bytes:
    if path.suffix.lower() == ".class":
        return path.read_bytes()
    if zipfile.is_zipfile(path):
        names = _classes_in_archive(path)
        if not names:
            raise ValueError("archive contains no .class files")
        wanted = class_name.replace(".", "/") + ".class" if class_name else names[0]
        with zipfile.ZipFile(path) as archive:
            return archive.read(wanted)
    raise ValueError("expected a .class file or a Java archive")


class JavaProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return tuple(
            CapabilityDescriptor(
                operation=operation,
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=(
                    "Pure-Python class metadata; no bytecode verification or Java runtime.",
                ),
            )
            for operation in _OPERATIONS
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        path = Path(target.path)
        if path.suffix.lower() in (".jar", ".war", ".ear") or path.suffix.lower() == ".class":
            return TargetSupport("supported")
        if target.format == "zip" and path.suffix.lower() in (".jar", ".war", ".ear"):
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported", reason="not a Java class or archive", code="target_format_unsupported"
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del profile
        path = Path(target.path)
        if operation == "inspect_java_archive":
            if not zipfile.is_zipfile(path):
                return err(AnalysisInputError(operation=operation, message="not a Java archive"))
            try:
                with zipfile.ZipFile(path) as archive:
                    names = _classes_in_archive(path)
                    manifest_text = ""
                    if "META-INF/MANIFEST.MF" in archive.namelist():
                        manifest_text = archive.read("META-INF/MANIFEST.MF").decode(
                            "utf-8", errors="replace"
                        )
                    packages = sorted(
                        {name.rsplit("/", 1)[0].replace("/", ".") for name in names if "/" in name}
                    )
                    main = next(
                        (
                            line.split(":", 1)[1].strip()
                            for line in manifest_text.splitlines()
                            if line.startswith("Main-Class:")
                        ),
                        None,
                    )
            except (OSError, zipfile.BadZipFile, ValueError) as cause:
                return err(AnalysisInputError(operation=operation, message=str(cause)))
            return ok(
                AnalysisExecution(
                    result={
                        "format": "java-archive",
                        "class_count": len(names),
                        "packages": packages[:500],
                        "main_class": main,
                        "classes": names[:2000],
                    },
                    provider=self.identity(),
                    limitations=(
                        "Class entries only; nested JARs and multi-release variants are not expanded.",
                    ),
                )
            )
        if operation == "search_java_classes":
            query = str(parameters.get("query") or "").lower()
            try:
                names = _classes_in_archive(path) if zipfile.is_zipfile(path) else [path.name]
            except (OSError, zipfile.BadZipFile) as cause:
                return err(AnalysisInputError(operation=operation, message=str(cause)))
            matches = [name for name in names if query in name.lower()]
            return ok(
                AnalysisExecution(
                    result={"query": query, "matches": matches[:1000], "count": len(matches)},
                    provider=self.identity(),
                )
            )
        if operation == "inspect_java_class":
            try:
                parsed = _parse_class(_read_class(path, parameters.get("class_name")))
            except (OSError, ValueError, zipfile.BadZipFile, KeyError) as cause:
                return err(AnalysisInputError(operation=operation, message=str(cause)))
            return ok(AnalysisExecution(result=parsed, provider=self.identity()))
        if operation == "decompile_java_class":
            vineflower = _vineflower()
            java = _java()
            if not vineflower or (vineflower[1] and not java):
                return err(
                    AnalysisCapabilityUnavailableError(
                        message="Vineflower or Java is not installed",
                        provider_id=_PROVIDER.id,
                        operation=operation,
                        reason="provider_unavailable",
                        remediation_action="Install a JDK and Vineflower, or set REA_JAVA/REA_VINEFLOWER.",
                    )
                )
            output = Path(tempfile.mkdtemp(prefix="rea-java-"))
            try:
                command = (
                    [str(java), "-jar", vineflower[0], str(path), str(output)]
                    if vineflower[1]
                    else [vineflower[0], str(path), str(output)]
                )
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=600,
                )
                if result.returncode != 0:
                    return err(
                        AnalysisInputError(operation=operation, message=result.stderr[-1000:])
                    )
                files = list(output.rglob("*.java"))
                return ok(
                    AnalysisExecution(
                        result={
                            "file_count": len(files),
                            "files": [str(item.relative_to(output)) for item in files[:200]],
                            "source": files[0].read_text(encoding="utf-8", errors="replace")[
                                :200000
                            ]
                            if files
                            else "",
                        },
                        provider=self.identity(),
                        limitations=("Vineflower output; not verified against a live JDK here.",),
                    )
                )
            except (OSError, subprocess.TimeoutExpired) as cause:
                return err(AnalysisInputError(operation=operation, message=str(cause)))
            finally:
                import shutil as _shutil

                _shutil.rmtree(output, ignore_errors=True)
        return err(
            AnalysisInputError(operation=operation, message=f"unsupported operation {operation}")
        )


__all__ = ["JavaProvider"]
