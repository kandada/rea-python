from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

from rea_mcp.domain.binary_target import parse_binary_target
from rea_mcp.providers.artifact import ArtifactProvider


def _target(path: Path):
    result = parse_binary_target(path)
    assert result.ok
    return result.value


def test_artifact_directory_and_pagination(tmp_path: Path) -> None:
    root = tmp_path / "files"
    root.mkdir()
    for index in range(5):
        (root / f"f{index}.txt").write_text(str(index), encoding="utf-8")
    result = ArtifactProvider().analyze(
        "inspect_artifact", _target(root), {"offset": 1, "limit": 2}, None
    )
    assert result.ok
    payload = result.value.result
    assert payload["entry_total"] == 5
    assert payload["returned_entry_count"] == 2
    assert payload["next_offset"] == 3
    assert payload["entries"][0]["path"] == "f1.txt"


def test_artifact_zip_and_tar(tmp_path: Path) -> None:
    archive = tmp_path / "a.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("dir/", b"")
        bundle.writestr("a.txt", b"a")
        bundle.writestr("b.txt", b"bb")
    result = ArtifactProvider().analyze("inspect_artifact", _target(archive), {}, None)
    assert result.ok
    assert result.value.result["entry_count"] == 2
    assert any(item["path"] == "b.txt" for item in result.value.result["entries"])

    tar_path = tmp_path / "a.tar"
    with tarfile.open(tar_path, "w") as bundle:
        data = b"hello"
        info = tarfile.TarInfo("hello.txt")
        info.size = len(data)
        bundle.addfile(info, io.BytesIO(data))
    tar_result = ArtifactProvider().analyze("inspect_artifact", _target(tar_path), {}, None)
    assert tar_result.ok
    assert tar_result.value.result["entries"][0]["path"] == "hello.txt"


def test_artifact_unsupported_operation_and_pck_error(tmp_path: Path) -> None:
    archive = tmp_path / "a.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("a.txt", b"a")
    provider = ArtifactProvider()
    assert not provider.analyze("other", _target(archive), {}, None).ok
    pck = tmp_path / "bad.pck"
    pck.write_bytes(b"GDPC")
    assert not provider.analyze("inspect_artifact", _target(pck), {}, None).ok
    assert provider.supports(_target(archive)).status == "supported"
