from __future__ import annotations

import zipfile
from pathlib import Path

from rea_mcp.domain.binary_target import parse_binary_target
from rea_mcp.providers.apk_signature import ApkSignatureProvider
from rea_mcp.providers.desktop_application import DesktopApplicationProvider
from rea_mcp.providers.gpu_code_objects import GpuCodeObjectsProvider
from rea_mcp.providers.il2cpp_metadata import Il2CppMetadataProvider
from tests.conftest import build_elf


def _target(path: Path):  # type: ignore[no-untyped-def]
    parsed = parse_binary_target(str(path))
    assert parsed.ok
    return parsed.value


def test_apk_signature_v1_and_absence(apk_file: Path, tmp_path: Path) -> None:
    provider = ApkSignatureProvider()
    absent = provider.analyze("inspect_apk_signature", _target(apk_file), {}, None)
    assert absent.ok
    assert absent.value.result["has_signatures"] is False

    signed = tmp_path / "signed.apk"
    with zipfile.ZipFile(signed, "w") as archive:
        archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        archive.writestr("META-INF/CERT.RSA", b"fake-certificate")
        archive.writestr("classes.dex", b"dex")
    result = provider.analyze("inspect_apk_signature", _target(signed), {}, None)
    assert result.ok
    data = result.value.result
    assert data["has_signatures"] is True
    assert data["v1"]["certificate_count"] == 1
    assert data["v1"]["certificates"][0]["path"] == "META-INF/CERT.RSA"


def test_desktop_application_triage(tmp_path: Path) -> None:
    root = tmp_path / "Game"
    (root / "Game_Data").mkdir(parents=True)
    (root / "Game_Data" / "global-metadata.dat").write_bytes(b"metadata")
    (root / "GameAssembly.dll").write_bytes(b"not a real pe")
    (root / "Game_Data" / "resources").mkdir()
    (root / "Game_Data" / "resources" / "app.asar").write_bytes(b"asar")
    result = DesktopApplicationProvider().analyze(
        "inspect_desktop_application", _target(root), {}, None
    )
    assert result.ok
    data = result.value.result
    assert data["candidate_count"] == 3
    assert {item["kind"] for item in data["candidates"]} == {
        "il2cpp-metadata",
        "unity",
        "electron",
    }
    assert data["next_probes"]


def test_gpu_code_object_discovery(tmp_path: Path) -> None:
    ptx = tmp_path / "kernel.ptx"
    ptx.write_text(".version 8.0\n.visible .entry main() { ret; }\n", encoding="utf-8")
    result = GpuCodeObjectsProvider().analyze("inspect_gpu_code_objects", _target(ptx), {}, None)
    assert result.ok
    assert result.value.result["has_gpu_objects"] is True
    assert any(item["kind"] == "ptx" for item in result.value.result["objects"])


def test_il2cpp_metadata_header(tmp_path: Path) -> None:
    path = tmp_path / "global-metadata.dat"
    header_size = 8 + 31 * 8
    sections = b"".join(
        header_size.to_bytes(4, "little", signed=True) + b"\x00" * 4 for _ in range(31)
    )
    path.write_bytes(b"\xaf\x1b\xb1\xfa" + (29).to_bytes(4, "little") + sections)
    result = Il2CppMetadataProvider().analyze("inspect_il2cpp_metadata", _target(path), {}, None)
    assert result.ok
    assert result.value.result["metadata_version"] == 29
    assert result.value.result["coverage"]["state"] == "complete"


def test_cubin_nv_info_parameters_and_registers(tmp_path: Path) -> None:
    import struct

    param = struct.pack("<BBH", 4, 0x17, 12)
    param += struct.pack("<IHHI", 0, 0, 0, 8 << 18)
    register = struct.pack("<BBH", 4, 0x2F, 8)
    register += struct.pack("<II", 0, 16)
    byte_decl = struct.pack("<BBH", 3, 0x19, 16)
    data = build_elf(
        {".nv.info": byte_decl + param + register, ".text": b"\x00" * 16},
        machine=190,
        elf_type=1,
    )
    path = tmp_path / "kernel.cubin"
    path.write_bytes(data)
    result = GpuCodeObjectsProvider().analyze("inspect_gpu_code_objects", _target(path), {}, None)
    assert result.ok
    cubin = next(item for item in result.value.result["objects"] if item["kind"] == "cubin")
    assert cubin["cubin"]["parameter_count"] == 1
    assert cubin["cubin"]["parameter_bytes"] == 16
    assert cubin["cubin"]["parameters"][0]["size"] == 8
    assert cubin["cubin"]["physical_registers"] == 16


def test_amdgpu_metadata_kernels(tmp_path: Path) -> None:
    import msgpack

    payload = msgpack.packb(
        {
            "amdhsa.kernels": [
                {
                    ".name": "vector_add",
                    ".symbol": "vector_add.kd",
                    ".sgpr_count": 8,
                    ".vgpr_count": 16,
                    ".agpr_count": 0,
                    ".kernarg_segment_size": 24,
                }
            ]
        },
        use_bin_type=True,
    )
    data = build_elf({".amdgpu_metadata": payload}, machine=224, elf_type=1)
    path = tmp_path / "kernel.hsaco"
    path.write_bytes(data)
    result = GpuCodeObjectsProvider().analyze("inspect_gpu_code_objects", _target(path), {}, None)
    assert result.ok
    amdgpu = next(item for item in result.value.result["objects"] if item["kind"] == "amdgpu")
    assert amdgpu["amdgpu"]["kernel_count"] == 1
    assert amdgpu["amdgpu"]["kernels"][0]["vgpr_count"] == 16


def test_apk_certificate_chain_facts() -> None:
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    from rea_mcp.providers.apk_signature import _certificate_chain

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "REA Test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    chain = _certificate_chain([der])
    assert chain["self_signed"] is True
    assert chain["all_valid_now"] is True
    assert chain["trust_verified"] is False


def test_il2cpp_dumper_bridge(monkeypatch, tmp_path: Path) -> None:

    from rea_mcp.providers.il2cpp_metadata import _run_il2cpp_dumper

    root = tmp_path / "dumper"
    package = root / "il2cpp_dumper_py"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "__main__.py").write_text(
        "import json, pathlib, sys\n"
        "out = pathlib.Path(sys.argv[3]); out.mkdir(parents=True, exist_ok=True)\n"
        "(out / 'script.json').write_text(json.dumps({'ScriptMethod': [{'Address': 4096, 'Name': 'Asm::Run', 'Signature': 'void()'}]}))\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("REA_IL2CPP_DUMPER", str(root))
    linked = _run_il2cpp_dumper("/tmp/bin", "/tmp/meta")
    assert linked["method_addresses_linked"] is True
    assert linked["method_addresses"][0]["rva"] == "0x1000"
    assert linked["method_addresses"][0]["name"] == "Asm::Run"
