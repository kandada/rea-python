"""Production wiring: the single place providers and the session are assembled."""

from __future__ import annotations

from ..application.session import BinarySession
from ..config.settings import AppConfig
from ..providers.android import AndroidProvider
from ..providers.apple import AssetCatalogProvider, KeyedArchiveProvider
from ..providers.artifact import ArtifactProvider
from ..providers.base import AnalysisProvider
from ..providers.binary_layout import BinaryLayoutProvider
from ..providers.dotnet import ManagedStaticProvider
from ..providers.engines import AdbProvider, ApktoolProvider, KunaProvider, SignalProvider
from ..providers.evm import EvmInterfaceProvider
from ..providers.firmware import FirmwareProvider
from ..providers.flutter import FlutterBuildProvider
from ..providers.go import GoBinaryProvider
from ..providers.harmony import HarmonyProvider
from ..providers.hopper import HopperProvider
from ..providers.javascript import JavaScriptApplicationProvider
from ..providers.network_capture import MitmproxyProvider, NetworkCaptureProvider
from ..providers.objdump import ObjdumpProvider
from ..providers.optional_engines import (
    BrowserProvider,
    FridaProvider,
    GhidraProvider,
    IdaProvider,
    JebProvider,
    RecordedCrashProvider,
)
from ..providers.pcap import PcapProvider
from ..providers.pe_resources import PeResourcesProvider
from ..providers.plist import PlistProvider
from ..providers.reference import ReferenceSourceProvider
from ..providers.registry import AnalysisProviderRegistry
from ..providers.rizin import RizinProvider
from ..providers.rust import RustBinaryProvider
from ..providers.sqlite import SqliteDatabaseProvider
from ..providers.wasm import WasmArtifactProvider


def build_providers() -> list[AnalysisProvider]:
    """Return the built-in providers in a stable order.

    Providers own disjoint operations; external-tool providers report an
    actionable unavailability reason when their tool is missing.
    """

    return [
        BinaryLayoutProvider(),
        GoBinaryProvider(),
        RustBinaryProvider(),
        ManagedStaticProvider(),
        SqliteDatabaseProvider(),
        ArtifactProvider(),
        AndroidProvider(),
        FlutterBuildProvider(),
        WasmArtifactProvider(),
        EvmInterfaceProvider(),
        PlistProvider(),
        ReferenceSourceProvider(),
        ObjdumpProvider(),
        RizinProvider(),
        PcapProvider(),
        FirmwareProvider(),
        ApktoolProvider(),
        AdbProvider(),
        SignalProvider(),
        KunaProvider(),
        GhidraProvider(),
        HopperProvider(),
        IdaProvider(),
        JebProvider(),
        FridaProvider(),
        BrowserProvider(),
        RecordedCrashProvider(),
        NetworkCaptureProvider(),
        MitmproxyProvider(),
        HarmonyProvider(),
        JavaScriptApplicationProvider(),
        KeyedArchiveProvider(),
        AssetCatalogProvider(),
        PeResourcesProvider(),
    ]


def create_registry(config: AppConfig) -> AnalysisProviderRegistry:
    return AnalysisProviderRegistry(build_providers(), config.analysis_provider)


def create_binary_session(config: AppConfig) -> BinarySession:
    """Wire the shared session used by both CLI and MCP adapters."""

    return BinarySession(create_registry(config))


__all__ = ["build_providers", "create_binary_session", "create_registry"]
