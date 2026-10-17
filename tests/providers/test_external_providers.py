from pathlib import Path

from rea_mcp.application.diagnostics import doctor_report
from rea_mcp.composition.factories import build_providers
from rea_mcp.domain.binary_target import parse_binary_target
from rea_mcp.providers.evm import EvmInterfaceProvider
from rea_mcp.providers.firmware import FirmwareProvider
from rea_mcp.providers.objdump import ObjdumpProvider
from rea_mcp.providers.pcap import PcapProvider
from rea_mcp.providers.reference import ReferenceSourceProvider
from rea_mcp.providers.rizin import RizinProvider
from rea_mcp.providers.wasm import WasmArtifactProvider


def _target(path: Path) -> object:
    result = parse_binary_target(path)
    assert result.ok
    return result.value


def test_doctor_report_lists_all_providers() -> None:
    report = doctor_report(build_providers())
    ids = {entry["id"] for entry in report["providers"]}
    assert {
        "binary-layout",
        "go",
        "rust",
        "dotnet",
        "sqlite",
        "artifacts",
        "android",
        "flutter",
        "wasm",
        "evm",
        "reference",
        "objdump",
        "rizin",
        "pcap",
        "firmware",
    } <= ids
    assert isinstance(report["healthy"], bool)


def test_capabilities_never_raise() -> None:
    for provider in (
        ObjdumpProvider(),
        RizinProvider(),
        PcapProvider(),
        FirmwareProvider(),
        EvmInterfaceProvider(),
        WasmArtifactProvider(),
        ReferenceSourceProvider(),
    ):
        assert provider.capabilities()


def test_wasm_structural_inspection(wasm_file: Path) -> None:
    result = WasmArtifactProvider().analyze("inspect_wasm_artifact", _target(wasm_file), {}, None)  # type: ignore[arg-type]
    assert result.ok
    assert result.value.result["valid"] is True
    assert result.value.result["version"] == 1
    assert result.value.result["section_count"] >= 1
    assert result.value.result["sections"][0]["name"] == "type"


def test_wasm_rejects_non_module(tmp_path: Path) -> None:
    path = tmp_path / "not.wasm"
    path.write_bytes(b"not wasm at all")
    result = WasmArtifactProvider().analyze("inspect_wasm_artifact", _target(path), {}, None)  # type: ignore[arg-type]
    assert not result.ok


def test_reference_source_inventory(source_dir: Path) -> None:
    result = ReferenceSourceProvider().analyze(
        "import_reference_source", _target(source_dir), {}, None
    )  # type: ignore[arg-type]
    assert result.ok
    paths = {entry["path"] for entry in result.value.result["files"]}
    assert "main.py" in paths
    assert "pkg/util.js" in paths
    # Excluded directory.
    assert not any("node_modules" in path for path in paths)
    assert result.value.result["languages"].get("Python") == 1
    assert result.value.result["languages"].get("JavaScript") == 1


def test_evm_unavailable_reports_capability_error(tmp_path: Path) -> None:
    provider = EvmInterfaceProvider()
    available = all(cap.available for cap in provider.capabilities())
    path = tmp_path / "code.bin"
    path.write_bytes(b"6080604052")
    result = provider.analyze("inspect_evm_interface", _target(path), {}, None)  # type: ignore[arg-type]
    if available:  # evmole installed
        assert result.ok
    else:
        assert not result.ok
        assert result.error.tag == "AnalysisCapabilityUnavailableError"


def test_pcap_unavailable_or_runs(pcap_file: Path) -> None:
    provider = PcapProvider()
    available = all(cap.available for cap in provider.capabilities())
    result = provider.analyze("inspect_pcap_capture", _target(pcap_file), {}, None)  # type: ignore[arg-type]
    if available:
        assert result.ok
    else:
        assert not result.ok


def test_firmware_unavailable_reports_reason(elf_file: Path) -> None:
    provider = FirmwareProvider()
    available = all(cap.available for cap in provider.capabilities())
    result = provider.analyze("inspect_firmware_regions", _target(elf_file), {}, None)
    if not available:
        # firmware supports only raw images; ELF is unsupported, so analyze may
        # still be called directly and must report an actionable error.
        assert not result.ok


def test_objdump_headers_when_available(elf_file: Path) -> None:
    provider = ObjdumpProvider()
    if not all(cap.available for cap in provider.capabilities()):
        result = provider.analyze("inspect_with_objdump", _target(elf_file), {}, None)
        assert not result.ok
        assert result.error.tag == "AnalysisCapabilityUnavailableError"


def test_plist_provider(plist_file: Path) -> None:
    from rea_mcp.providers.plist import PlistProvider

    result = PlistProvider().analyze("inspect_plist", _target(plist_file), {}, None)
    assert result.ok
    assert result.value.result["plist_format"] == "xml"
    assert "CFBundleIdentifier" in result.value.result["top_level_keys"]
