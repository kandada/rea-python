from pathlib import Path

from rea_mcp.domain.binary_target import parse_binary_target
from rea_mcp.providers.android import AndroidProvider
from rea_mcp.providers.apple import KeyedArchiveProvider
from rea_mcp.providers.artifact import ArtifactProvider
from rea_mcp.providers.dotnet import ManagedStaticProvider
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


def test_har_capture_pages(har_file: Path) -> None:
    result = NetworkCaptureProvider().analyze(
        "inspect_network_capture",
        _target(har_file),
        {"offset": 1, "limit": 1},
        None,
    )  # type: ignore[arg-type]
    assert result.ok
    data = result.value.result
    assert data["request_total"] == 2
    assert data["requests_offset"] == 1
    assert len(data["requests"]) == 1
    assert data["next_offset"] is None


def test_artifact_pages(zip_file: Path) -> None:
    result = ArtifactProvider().analyze(
        "inspect_artifact",
        _target(zip_file),
        {"offset": 1, "limit": 1},
        None,
    )  # type: ignore[arg-type]
    assert result.ok
    data = result.value.result
    assert data["entry_total"] == 2
    assert data["returned_entry_count"] == 1
    assert data["entries_offset"] == 1
    assert data["next_offset"] is None
    assert data["entries"][0]["path"] == "dir/b.txt"


def test_javascript_application_pages(js_dir: Path) -> None:
    result = JavaScriptApplicationProvider().analyze(
        "analyze_javascript_application",
        _target(js_dir),
        {"module_limit": 1, "edge_limit": 1},
        None,
    )  # type: ignore[arg-type]
    assert result.ok
    data = result.value.result
    assert data["module_count"] == 3
    assert len(data["modules"]) == 1
    assert data["next_module_offset"] == 1
    assert data["edge_count"] >= 2
    assert len(data["edges"]) == 1
    assert data["next_edge_offset"] == 1


def test_android_package_pages(apk_file: Path) -> None:
    result = AndroidProvider().analyze(
        "inspect_android_package",
        _target(apk_file),
        {"offset": 0, "limit": 1},
        None,
    )  # type: ignore[arg-type]
    assert result.ok
    data = result.value.result
    assert data["permissions_offset"] == 0
    assert "permissions_total" in data
    assert "component_totals" in data


def test_managed_members_page(pe_clr_file: Path) -> None:
    result = ManagedStaticProvider().analyze(
        "inspect_managed_members",
        _target(pe_clr_file),
        {"offset": 0, "limit": 1},
        None,
    )  # type: ignore[arg-type]
    assert result.ok
    data = result.value.result
    assert data["types_total"] >= 1
    assert len(data["types"]) <= 1
    assert data["types_offset"] == 0
    if data["types"]:
        assert "methods_offset" in data["types"][0]
        assert "methods_total" in data["types"][0]


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


def test_electron_fuses(electron_file: Path) -> None:
    from rea_mcp.providers.electron import ElectronFuseProvider

    result = ElectronFuseProvider().analyze(
        "inspect_electron_fuses", _target(electron_file), {}, None
    )
    assert result.ok
    assert result.value.result["is_electron"] is True
    fuses = result.value.result["fuses"]
    assert fuses["RunAsNode"] == "enabled"
    assert fuses["EnableNodeCliInspectArguments"] == "disabled"


def test_entitlements(plist_file: Path) -> None:
    from rea_mcp.providers.apple import EntitlementsProvider

    result = EntitlementsProvider().analyze("inspect_entitlements", _target(plist_file), {}, None)
    assert result.ok
    assert result.value.result["is_entitlements"] is True
    assert "CFBundleIdentifier" in result.value.result["entitlements"]


def test_compare_network_captures(har_file: Path, har_file_b: Path) -> None:
    from rea_mcp.providers.network_capture import compare_capture_files

    result = compare_capture_files(str(har_file), str(har_file_b))
    assert result.ok
    assert result.value["status"] == "changed"
    assert result.value["added_count"] == 1
    assert result.value["removed_count"] == 1


def test_pcap_fields(pcap_dns_file: Path) -> None:
    from rea_mcp.providers.pcap import PcapProvider

    result = PcapProvider().analyze("inspect_pcap_capture", _target(pcap_dns_file), {}, None)  # type: ignore[arg-type]
    assert result.ok
    fields = result.value.result["fields"]
    assert fields["packet_count"] == 1
    assert fields["dns_queries"] == ["example.com"]
    assert "DNS" in fields["protocols"]
    assert "192.168.0.1->8.8.8.8" in fields["endpoints"]


def test_pcap_not_a_capture(plain_file: Path) -> None:
    from rea_mcp.providers.pcap import PcapProvider

    result = PcapProvider().analyze("inspect_pcap_capture", _target(plain_file), {}, None)  # type: ignore[arg-type]
    assert not result.ok


def test_firmware_signatures(firmware_file: Path) -> None:
    from rea_mcp.providers.firmware import FirmwareProvider

    result = FirmwareProvider().analyze(
        "inspect_firmware_regions", _target(firmware_file), {}, None
    )  # type: ignore[arg-type]
    assert result.ok
    descriptions = {region["description"] for region in result.value.result["regions"]}
    assert "U-Boot uImage header" in descriptions
    assert "SquashFS filesystem" in descriptions
    offsets = {region["offset"] for region in result.value.result["regions"]}
    assert 0x1000 in offsets


def test_interface_builder(interface_builder_file: Path) -> None:
    from rea_mcp.providers.apple import InterfaceBuilderProvider

    result = InterfaceBuilderProvider().analyze(
        "inspect_interface_builder", _target(interface_builder_file), {}, None
    )  # type: ignore[arg-type]
    assert result.ok
    assert result.value.result["is_interface_builder"] is True
    assert set(result.value.result["class_names"]) == {"NSView", "NSButton"}


def test_compare_managed_members(pe_clr_file: Path, pe_clr_file_b: Path) -> None:
    from rea_mcp.providers.dotnet import compare_managed_members

    result = compare_managed_members(str(pe_clr_file), str(pe_clr_file_b))
    assert result.ok
    assert result.value["status"] == "changed"
    assert any("MyMethod" in member for member in result.value["removed"])
    assert any("OtherMethod" in member for member in result.value["added"])


def test_signal_capture_inventory(vcd_file: Path) -> None:
    from rea_mcp.providers.signals import SignalCaptureProvider

    result = SignalCaptureProvider().analyze("inspect_signal_capture", _target(vcd_file), {}, None)  # type: ignore[arg-type]
    assert result.ok
    assert result.value.result["signal_count"] == 1
    assert "tx" in result.value.result["signals"]


def test_decode_uart(vcd_file: Path) -> None:
    from rea_mcp.providers.signals import SignalCaptureProvider

    result = SignalCaptureProvider().analyze("decode_uart_capture", _target(vcd_file), {}, None)  # type: ignore[arg-type]
    assert result.ok
    assert result.value.result["bytes"] == [ord("O"), ord("K")]
    assert result.value.result["ascii"] == "OK"


def test_crash_dump(crash_dump_file: Path) -> None:
    from rea_mcp.providers.crash import CrashDumpProvider

    result = CrashDumpProvider().analyze("inspect_crash_dump", _target(crash_dump_file), {}, None)  # type: ignore[arg-type]
    assert result.ok
    assert result.value.result["signal"] == "SIGSEGV"
    assert len(result.value.result["backtrace"]) == 2
    assert result.value.result["registers"]["rip"].startswith("0x")


def test_inspect_cdp_targets(plain_file: Path) -> None:
    import http.server
    import json
    import threading

    from rea_mcp.providers.cdp import CdpProvider

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/json/version":
                body: object = {"Browser": "Chrome/120", "Protocol-Version": "1.3"}
            elif self.path == "/json/list":
                body = [
                    {
                        "type": "page",
                        "title": "Example",
                        "url": "https://example.com/",
                        "webSocketDebuggerUrl": "ws://127.0.0.1/1",
                    }
                ]
            else:
                self.send_response(404)
                self.end_headers()
                return
            payload = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args: object) -> None:
            del args

    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        endpoint = f"http://127.0.0.1:{server.server_port}"
        result = CdpProvider().analyze(
            "inspect_cdp_targets", _target(plain_file), {"endpoint": endpoint}, None
        )  # type: ignore[arg-type]
        assert result.ok
        assert result.value.result["browser"] == "Chrome/120"
        assert result.value.result["target_count"] == 1
        assert result.value.result["targets"][0]["attachable"] is True
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_inspect_cdp_targets_unavailable(plain_file: Path) -> None:
    from rea_mcp.providers.cdp import CdpProvider

    result = CdpProvider().analyze(
        "inspect_cdp_targets", _target(plain_file), {"endpoint": "http://127.0.0.1:1"}, None
    )  # type: ignore[arg-type]
    assert not result.ok


def test_capture_cdp_network_with_fake_websocket(monkeypatch: object, plain_file: Path) -> None:
    import http.server
    import json
    import threading
    import types

    from rea_mcp.providers.cdp import CdpProvider

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = [
                {
                    "type": "page",
                    "url": "https://example.com/",
                    "webSocketDebuggerUrl": "ws://127.0.0.1/1",
                }
            ]
            payload = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args: object) -> None:
            del args

    class _FakeConnection:
        def __init__(self) -> None:
            self._delivered = False

        def settimeout(self, value: float) -> None:
            del value

        def send(self, data: str) -> None:
            del data

        def recv(self) -> str:
            if not self._delivered:
                self._delivered = True
                return json.dumps(
                    {
                        "method": "Network.requestWillBeSent",
                        "params": {
                            "requestId": "1",
                            "request": {"method": "GET", "url": "https://example.com/"},
                            "type": "Document",
                        },
                    }
                )
            raise TimeoutError

        def close(self) -> None:
            return None

    fake_websocket = types.SimpleNamespace(
        create_connection=lambda url, timeout=5: _FakeConnection()
    )
    monkeypatch.setattr(  # type: ignore[attr-defined]
        "rea_mcp.providers.cdp.optional_import",
        lambda name: fake_websocket if name == "websocket" else None,
    )
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        endpoint = f"http://127.0.0.1:{server.server_port}"
        result = CdpProvider().analyze(
            "capture_cdp_network",
            _target(plain_file),
            {"endpoint": endpoint, "duration": 0.05},
            None,
        )  # type: ignore[arg-type]
        assert result.ok
        assert result.value.result["request_count"] == 1
        request = result.value.result["requests"][0]
        assert request["method"] == "GET"
        assert request["url"] == "https://example.com/"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def _script(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(0o755)
    return path


def test_pcapng_fields(pcapng_dns_file: Path) -> None:
    from rea_mcp.providers.pcap import PcapProvider

    result = PcapProvider().analyze("inspect_pcap_capture", _target(pcapng_dns_file), {}, None)  # type: ignore[arg-type]
    assert result.ok
    fields = result.value.result["fields"]
    assert fields["packet_count"] == 1
    assert fields["dns_queries"] == ["example.com"]
    assert fields["linktypes"] == [1]


def test_pcap_tshark_enrichment(monkeypatch: object, tmp_path: Path, pcap_dns_file: Path) -> None:
    from rea_mcp.providers.pcap import PcapProvider

    script = _script(
        tmp_path,
        "tshark",
        'for arg in "$@"; do\n'
        '  if [ "$arg" = "io,phs" ]; then echo "Protocol Hierarchy"; exit 0; fi\n'
        "done\nexit 0\n",
    )
    monkeypatch.setenv("REA_TSHARK", str(script))  # type: ignore[attr-defined]
    result = PcapProvider().analyze("inspect_pcap_capture", _target(pcap_dns_file), {}, None)  # type: ignore[arg-type]
    assert result.ok
    assert "Protocol Hierarchy" in result.value.result["protocol_hierarchy"]


def test_firmware_binwalk_enrichment(
    monkeypatch: object, tmp_path: Path, firmware_file: Path
) -> None:
    from rea_mcp.providers.firmware import FirmwareProvider

    script = _script(
        tmp_path,
        "binwalk",
        'echo "0        0x0             U-Boot uImage header"\n'
        'echo "4096     0x1000          SquashFS filesystem"\n',
    )
    monkeypatch.setenv("REA_BINWALK", str(script))  # type: ignore[attr-defined]
    result = FirmwareProvider().analyze(
        "inspect_firmware_regions", _target(firmware_file), {}, None
    )  # type: ignore[arg-type]
    assert result.ok
    assert len(result.value.result["binwalk_regions"]) == 2
    assert result.value.result["binwalk_regions"][1]["offset"] == 4096


def test_packet_fields(pcap_dns_file: Path) -> None:
    from rea_mcp.providers.pcap import PcapProvider

    result = PcapProvider().analyze(
        "inspect_packet_fields", _target(pcap_dns_file), {"limit": 10}, None
    )  # type: ignore[arg-type]
    assert result.ok
    fields = result.value.result["fields"]
    assert fields["packet_count"] == 1
    packet = fields["packets"][0]
    assert packet["src"] == "192.168.0.1"
    assert packet["dst"] == "8.8.8.8"
    assert packet["dns_query"] == "example.com"


def test_firmware_extract(firmware_file: Path, tmp_path: Path) -> None:
    from rea_mcp.providers.firmware import FirmwareProvider

    output = tmp_path / "extracted"
    result = FirmwareProvider().analyze(
        "extract_firmware",
        _target(firmware_file),
        {"output_directory": str(output)},
        None,
    )  # type: ignore[arg-type]
    assert result.ok
    assert result.value.result["extracted_count"] == 2
    for item in result.value.result["extracted"]:
        assert Path(item["path"]).is_file()


def test_android_manifest_components_real() -> None:
    import os

    import pytest as _pytest

    fixture = os.environ.get("REA_APK_FIXTURE")
    if not fixture or not Path(fixture).is_file():
        _pytest.skip("requires REA_APK_FIXTURE (a real APK with a manifest)")
    from rea_mcp.providers.android import AndroidProvider

    result = AndroidProvider().analyze("inspect_android_package", _target(Path(fixture)), {}, None)  # type: ignore[arg-type]
    assert result.ok
    facts = result.value.result
    assert facts["package"]
    assert any((facts.get("components") or {}).values())


def test_dmg_inventory(tmp_path: Path) -> None:
    import struct

    from rea_mcp.providers.artifact import ArtifactProvider

    path = tmp_path / "sample.dmg"
    trailer = bytearray(512)
    trailer[0:4] = b"koly"
    struct.pack_into(">I", trailer, 4, 4)
    struct.pack_into(">Q", trailer, 24, 4096)
    struct.pack_into(">Q", trailer, 32, 8192)
    struct.pack_into(">Q", trailer, 216, 12288)
    struct.pack_into(">Q", trailer, 224, 256)
    struct.pack_into(">Q", trailer, 492, 16)
    path.write_bytes(b"\x00" * 128 + bytes(trailer))
    result = ArtifactProvider().analyze("inspect_artifact", _target(path), {}, None)  # type: ignore[arg-type]
    assert result.ok
    data = result.value.result
    assert data["format"] == "dmg"
    assert data["dmg"]["version"] == 4
    assert data["dmg"]["data_fork_offset"] == 4096
    assert data["dmg"]["sector_count"] == 16


def test_asar_integrity(asar_integrity_file: Path) -> None:
    from rea_mcp.providers.javascript import JavaScriptApplicationProvider

    result = JavaScriptApplicationProvider().analyze(
        "analyze_javascript_application", _target(asar_integrity_file), {}, None
    )  # type: ignore[arg-type]
    assert result.ok
    integrity = result.value.result["asar_integrity"]
    assert integrity["entry_count"] == 1
    assert integrity["algorithms"] == ["SHA256"]
    entry = integrity["entries"][0]
    assert entry["path"] == "main.js"
    assert entry["block_count"] == 1
