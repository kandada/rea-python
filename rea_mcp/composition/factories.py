"""Production wiring: the single place providers and the session are assembled."""

from __future__ import annotations

from ..application.session import BinarySession
from ..config.settings import AppConfig
from ..providers.android import AndroidProvider
from ..providers.android_deep import AndroidDeepProvider
from ..providers.apk_signature import ApkSignatureProvider
from ..providers.apple import (
    AssetCatalogProvider,
    EntitlementsProvider,
    InterfaceBuilderProvider,
    KeyedArchiveProvider,
)
from ..providers.artifact import ArtifactProvider
from ..providers.base import AnalysisProvider
from ..providers.binary_layout import BinaryLayoutProvider
from ..providers.byte_tools import ByteEntropyProvider, NativeBytesProvider
from ..providers.cdp import CdpProvider
from ..providers.crash import CrashDumpProvider
from ..providers.debug_sessions import DebugSessionProvider
from ..providers.desktop_application import DesktopApplicationProvider
from ..providers.dotnet import ManagedStaticProvider
from ..providers.dotnet_decompiler import CSharpDecompilerProvider
from ..providers.electron import ElectronFuseProvider
from ..providers.elf_notes import ElfNotesProvider
from ..providers.engines import (
    AdbProvider,
    ApktoolProvider,
    JadxProvider,
    KunaProvider,
    SignalProvider,
)
from ..providers.erlang_beam import ErlangBeamProvider
from ..providers.evm import EvmInterfaceProvider
from ..providers.firmware import FirmwareProvider
from ..providers.flutter import FlutterBuildProvider
from ..providers.go import GoBinaryProvider
from ..providers.gpu_code_objects import GpuCodeObjectsProvider
from ..providers.harmony import HarmonyProvider
from ..providers.hopper import HopperProvider
from ..providers.il2cpp_metadata import Il2CppMetadataProvider
from ..providers.javascript import JavaScriptApplicationProvider
from ..providers.model_artifact import ModelArtifactProvider
from ..providers.native_exports import NativeExportsProvider
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
from ..providers.pe_certificates import PeCertificatesProvider
from ..providers.pe_resources import PeResourcesProvider
from ..providers.plist import PlistProvider
from ..providers.python_pyc import PythonPycProvider
from ..providers.reference import ReferenceSourceProvider
from ..providers.registry import AnalysisProviderRegistry
from ..providers.rizin import RizinProvider
from ..providers.rust import RustBinaryProvider
from ..providers.signals import SignalCaptureProvider
from ..providers.sqlite import SqliteDatabaseProvider
from ..providers.wasm import WasmArtifactProvider
from ..providers.web_runtime import WebRuntimeProvider


def build_providers() -> list[AnalysisProvider]:
    """Return the built-in providers in a stable order.

    Providers own disjoint operations; external-tool providers report an
    actionable unavailability reason when their tool is missing.
    """

    return [
        BinaryLayoutProvider(),
        ApkSignatureProvider(),
        DesktopApplicationProvider(),
        GpuCodeObjectsProvider(),
        Il2CppMetadataProvider(),
        ByteEntropyProvider(),
        NativeBytesProvider(),
        ElfNotesProvider(),
        ErlangBeamProvider(),
        NativeExportsProvider(),
        ModelArtifactProvider(),
        PythonPycProvider(),
        PeCertificatesProvider(),
        GoBinaryProvider(),
        RustBinaryProvider(),
        ManagedStaticProvider(),
        CSharpDecompilerProvider(),
        SqliteDatabaseProvider(),
        ArtifactProvider(),
        AndroidProvider(),
        AndroidDeepProvider(),
        FlutterBuildProvider(),
        WasmArtifactProvider(),
        EvmInterfaceProvider(),
        PlistProvider(),
        ReferenceSourceProvider(),
        ObjdumpProvider(),
        RizinProvider(),
        PcapProvider(),
        FirmwareProvider(),
        SignalCaptureProvider(),
        CrashDumpProvider(),
        CdpProvider(),
        WebRuntimeProvider(),
        DebugSessionProvider(),
        ApktoolProvider(),
        JadxProvider(),
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
        EntitlementsProvider(),
        InterfaceBuilderProvider(),
        ElectronFuseProvider(),
        PeResourcesProvider(),
    ]


def create_registry(config: AppConfig) -> AnalysisProviderRegistry:
    return AnalysisProviderRegistry(build_providers(), config.analysis_provider)


def create_binary_session(config: AppConfig) -> BinarySession:
    """Wire the shared session used by both CLI and MCP adapters."""

    return BinarySession(create_registry(config))


__all__ = ["build_providers", "create_binary_session", "create_registry"]
