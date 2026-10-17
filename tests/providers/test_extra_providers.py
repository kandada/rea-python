from pathlib import Path

from rea_mcp.domain.binary_target import parse_binary_target
from rea_mcp.providers.apple import KeyedArchiveProvider
from rea_mcp.providers.harmony import HarmonyProvider
from rea_mcp.providers.javascript import JavaScriptApplicationProvider
from rea_mcp.providers.network_capture import NetworkCaptureProvider
from rea_mcp.providers.pe_resources import PeResourcesProvider


def _target(path: Path) -> object:
    result = parse_binary_target(path)
    assert result.ok
    return result.value


def test_har_capture(har_file: Path) -> None:
    result = NetworkCaptureProvider().analyze(
        "inspect_network_capture", _target(har_file), {}, None
    )  # type: ignore[arg-type]
    assert result.ok
    assert result.value.result["capture_format"] == "har"
    assert result.value.result["entry_count"] == 2
    hosts = result.value.result["hosts"]
    assert hosts["example.com"] == 1
    assert hosts["api.example.com"] == 1


def test_saz_capture(saz_file: Path) -> None:
    result = NetworkCaptureProvider().analyze(
        "inspect_network_capture", _target(saz_file), {}, None
    )  # type: ignore[arg-type]
    assert result.ok
    assert result.value.result["capture_format"] == "saz"
    assert result.value.result["session_count"] == 1
    assert "200 OK" in result.value.result["sessions"][0]["status"]


def test_harmony_hap(hap_file: Path) -> None:
    result = HarmonyProvider().analyze("inspect_harmony_package", _target(hap_file), {}, None)  # type: ignore[arg-type]
    assert result.ok
    assert result.value.result["bundle_name"] == "com.example.app"
    assert result.value.result["version_code"] == 7
    assert result.value.result["abc_files"] == ["ets/entry.abc"]


def test_javascript_directory(js_dir: Path) -> None:
    result = JavaScriptApplicationProvider().analyze(
        "analyze_javascript_application", _target(js_dir), {}, None
    )  # type: ignore[arg-type]
    assert result.ok
    assert result.value.result["module_count"] == 3
    edges = {(edge["from"], edge["to"]) for edge in result.value.result["edges"]}
    assert ("main.js", "./renderer") in edges
    assert ("renderer.js", "./util") in edges
    electron = result.value.result["electron"]
    assert electron["is_electron"] is True
    assert "ipcMain" in electron["roles"]


def test_javascript_asar(asar_file: Path) -> None:
    result = JavaScriptApplicationProvider().analyze(
        "analyze_javascript_application", _target(asar_file), {}, None
    )  # type: ignore[arg-type]
    assert result.ok
    edges = {(edge["from"], edge["to"]) for edge in result.value.result["edges"]}
    assert ("main.js", "./lib/util") in edges
    assert result.value.result["electron"]["is_electron"] is True


def test_keyed_archive(keyed_archive_file: Path) -> None:
    result = KeyedArchiveProvider().analyze(
        "inspect_keyed_archive", _target(keyed_archive_file), {}, None
    )  # type: ignore[arg-type]
    assert result.ok
    assert result.value.result["is_keyed_archive"] is True
    assert "NSString" in result.value.result["class_names"]
    assert result.value.result["top_level_keys"] == ["root"]


def test_pe_resources(pe_resources_file: Path) -> None:
    result = PeResourcesProvider().analyze(
        "inspect_pe_resources", _target(pe_resources_file), {}, None
    )  # type: ignore[arg-type]
    assert result.ok
    assert result.value.result["has_resources"] is True
    assert result.value.result["types"][0]["type"] == "icon"


def test_pe_without_resources(pe_file: Path) -> None:
    result = PeResourcesProvider().analyze("inspect_pe_resources", _target(pe_file), {}, None)  # type: ignore[arg-type]
    assert result.ok
    assert result.value.result["has_resources"] is False


def test_asset_catalog(asset_catalog_file: Path) -> None:
    from rea_mcp.providers.apple import AssetCatalogProvider

    result = AssetCatalogProvider().analyze(
        "inspect_asset_catalog", _target(asset_catalog_file), {}, None
    )  # type: ignore[arg-type]
    assert result.ok
    assert result.value.result["is_asset_catalog"] is True
    assert result.value.result["version"] == 1
    assert "RenditionName" in result.value.result["strings"]


def test_asset_catalog_negative(plain_file: Path) -> None:
    from rea_mcp.providers.apple import AssetCatalogProvider

    result = AssetCatalogProvider().analyze("inspect_asset_catalog", _target(plain_file), {}, None)  # type: ignore[arg-type]
    assert result.ok
    assert result.value.result["is_asset_catalog"] is False


def test_mitmproxy_availability_shape() -> None:
    from rea_mcp.providers.network_capture import MitmproxyProvider

    provider = MitmproxyProvider()
    capability = provider.capabilities()[0]
    assert capability.operation == "capture_live_network"
    if not capability.available:
        assert capability.reason


def test_macho_export_trie_in_layout(macho_exports_file: Path) -> None:
    from rea_mcp.providers.binary_layout import BinaryLayoutProvider

    result = BinaryLayoutProvider().analyze(
        "inspect_binary_layout", _target(macho_exports_file), {}, None
    )  # type: ignore[arg-type]
    assert result.ok
    assert "main" in result.value.result["exports"]
