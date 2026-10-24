"""Caller-visible tool/command contracts.

Each contract names an operation, its pydantic input model (used for both CLI
validation and MCP input schema), a description, and whether it requires an open
target.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..providers.base import AnalysisProvider


class _Input(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=False)


class OpenBinaryInput(_Input):
    path: str = Field(min_length=1, description="Absolute or relative path to the target.")
    provider_id: str | None = Field(
        default=None, description="Explicit provider id, or omit for auto."
    )
    target_kind: str | None = None
    format_hint: str | None = None


class CloseBinaryInput(_Input):
    snapshot_path: str | None = Field(
        default=None, description="Optional path to write a snapshot."
    )
    overwrite: bool = False


class SessionInput(_Input):
    pass


class GetEvidenceBundleInput(_Input):
    full: bool = Field(
        default=False, description="Return the complete bundle instead of a summary."
    )


class AnalysisInput(_Input):
    path: str | None = Field(
        default=None, description="Optional target path; uses the open target otherwise."
    )


class PagedAnalysisInput(AnalysisInput):
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=256, ge=1, le=1000)


class ManagedArtifactInput(AnalysisInput):
    detail: Literal["complete", "summary"] = "complete"


class TwoPathsInput(_Input):
    left: str = Field(min_length=1)
    right: str = Field(min_length=1)


class FeatureInput(_Input):
    path: str = Field(min_length=1)
    feature: str = Field(min_length=1)


class NodeTraceInput(_Input):
    path: str = Field(min_length=1)
    node: str = Field(min_length=1)


class ExportShapeInput(_Input):
    left: str = Field(min_length=1)
    right: str = Field(min_length=1)
    module: str = Field(min_length=1)
    export_name: str = Field(min_length=1)


class Il2CppInput(AnalysisInput):
    binary_path: str | None = None


class MatchNativeInput(_Input):
    left: str = Field(min_length=1)
    right: str = Field(min_length=1)
    query: str | None = None
    limit: int = Field(default=100, ge=1, le=1000)


class CompareWasmInput(_Input):
    left: str = Field(min_length=1)
    right: str = Field(min_length=1)
    selection: Literal["both", "imports", "exports"] = "both"


class ManagedPathInput(_Input):
    path: str = Field(min_length=1)


class VerifyManagedBoundariesInput(_Input):
    managed: str = Field(min_length=1)
    boundaries: list[str] = Field(min_length=1)


class ManagedJsonInput(_Input):
    path: str = Field(min_length=1)


class ManagedMembersInput(PagedAnalysisInput):
    method_offset: int = Field(default=0, ge=0)
    method_limit: int = Field(default=64, ge=1, le=1000)
    type_names: list[str] | None = None
    detail: Literal["complete", "summary"] = "complete"
    include_bodies: bool | None = None


class JavaScriptInput(PagedAnalysisInput):
    module_offset: int = Field(default=0, ge=0)
    module_limit: int = Field(default=500, ge=1, le=1000)
    edge_offset: int = Field(default=0, ge=0)
    edge_limit: int = Field(default=500, ge=1, le=1000)


class SqliteInput(AnalysisInput):
    table: str | None = Field(default=None, description="Read a bounded sample from this table.")
    row_limit: int = Field(default=20, ge=0, le=1000)


class SignalDecodeInput(AnalysisInput):
    channel: str | None = Field(default=None, description="VCD signal name to decode.")
    baud: int = Field(default=9600, ge=1, le=10_000_000)


class ProvidersInput(_Input):
    pass


class EvidenceExportInput(_Input):
    path: str = Field(min_length=1)


class EvidenceImportInput(_Input):
    path: str = Field(min_length=1)


class CommonKnowledgeInput(_Input):
    path: str = Field(min_length=1)


class AnalysisViewInput(_Input):
    source: str = Field(description="Path to a saved Evidence record or bundle JSON.")
    view: Literal[
        "summary",
        "record",
        "page",
        "environment-manifest",
        "javascript-facts",
        "javascript",
        "managed",
        "managed-members",
        "desktop-application",
    ] = "summary"
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=64, ge=1, le=1000)
    paths: list[str] | None = None
    property_keys: list[str] | None = None
    evidence_id: str | None = None
    collection: str | None = None


class SetupInput(_Input):
    path: str | None = Field(default=None, description="Optional client config path to write.")
    overwrite: bool = False


class MethodInput(AnalysisInput):
    method: str = ""
    type: str | None = None
    token: str | None = None
    rva: str | None = None
    signature: str | None = None


class RecordUnknownToolInput(_Input):
    question: str = Field(min_length=1)
    domain: str = Field(min_length=1)
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    required_authority: str | None = None
    required_confidence: Literal["observed", "derived", "inferred"] = "observed"


class UpdateUnknownToolInput(_Input):
    unknown_id: str = Field(min_length=1)
    status: Literal["open", "investigating", "blocked", "contradicted", "resolved"]
    severity: Literal["low", "medium", "high", "critical"] | None = None
    resolution: dict[str, Any] | None = None


class SnapshotExportToolInput(_Input):
    path: str = Field(min_length=1)
    out: str = Field(min_length=1)
    provider_id: str | None = None
    overwrite: bool = False


class SnapshotImportToolInput(_Input):
    path: str = Field(min_length=1)
    source: str = Field(min_length=1)
    provider_id: str | None = None


class CompareCapturesInput(_Input):
    left: str = Field(min_length=1, description="Left HAR/SAZ capture path.")
    right: str = Field(min_length=1, description="Right HAR/SAZ capture path.")


class ObligationInput(_Input):
    name: str = Field(min_length=1)
    kind: str = "function"
    required_facets: list[str] = Field(default_factory=list)
    provided_facets: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)


class BuildLedgerInput(_Input):
    obligations: list[ObligationInput] = Field(default_factory=list)


class EvaluateCoverageInput(_Input):
    ledger: dict[str, Any]


class FunctionInput(AnalysisInput):
    function: str = "main"
    limit: int = Field(default=200, ge=1, le=10000)


class SearchInput(AnalysisInput):
    query: str = Field(min_length=1)
    limit: int = Field(default=100, ge=1, le=10000)


class ManagedCSharpInput(AnalysisInput):
    type: str = Field(min_length=1)
    method: str | None = None
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=500, ge=1, le=1000)
    max_bytes: int = Field(default=64_000, ge=0, le=10_000_000)


class DecompileInput(AnalysisInput):
    function: str = "main"
    max_bytes: int = Field(default=64_000, ge=0, le=10_000_000)


class XrefsInput(AnalysisInput):
    address: str | None = None
    function: str = "main"


class InstructionsInput(AnalysisInput):
    address: str = "entry0"
    count: int = Field(default=64, ge=1, le=4096)
    limit: int = Field(default=200, ge=1, le=10000)
    start: str | None = None
    stop: str | None = None


class CaptureInput(_Input):
    command: list[str] = Field(min_length=1)
    timeout: float = Field(default=30.0, gt=0, le=3600)
    cwd: str | None = None


class CompareInput(_Input):
    left: str = Field(min_length=1, description="Path to a left Evidence record JSON.")
    right: str = Field(min_length=1, description="Path to a right Evidence record JSON.")


class ObserveWebPageInput(_Input):
    url: str = Field(min_length=1, description="Page URL to observe.")
    timeout: float = Field(default=30.0, gt=0, le=600)


class CdpEndpointInput(_Input):
    endpoint: str | None = Field(
        default=None, description="CDP base URL; defaults to REA_CDP_URL or 127.0.0.1:9222."
    )


class CaptureCdpInput(CdpEndpointInput):
    duration: float = Field(default=5.0, gt=0, le=600)
    target_url: str | None = None


class AndroidClassInput(AnalysisInput):
    class_name: str = Field(min_length=1, description="Fully-qualified class name.")
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=500, ge=1, le=1000)


class AndroidAppInfoInput(_Input):
    package: str = Field(min_length=1, description="Android package name.")


class AdbShellInput(_Input):
    command: list[str] = Field(min_length=1, description="Arguments passed to 'adb shell'.")
    timeout: float = Field(default=60.0, gt=0, le=3600)


class FridaDeviceInput(_Input):
    device: str | None = Field(
        default=None, description="Frida device id; first device by default."
    )


class AdbToolInput(_Input):
    serial: str | None = None
    scope: str | None = None
    package: str | None = None
    output_directory: str | None = None
    count: int | None = None
    buffer: str | None = None
    pid: int | None = None
    device_path: str | None = None
    local_path: str | None = None
    overwrite: bool | None = None
    namespace: str | None = None
    key: str | None = None
    query: str | None = None
    apk_path: str | None = None
    replace: bool | None = None
    action: str | None = None
    data_uri: str | None = None
    component: str | None = None
    extras: list[dict[str, Any]] | None = None
    timeout: float | None = None
    command: list[str] | None = None


class PacketFieldsInput(AnalysisInput):
    limit: int = Field(default=500, ge=1, le=100_000)


class FirmwareExtractInput(AnalysisInput):
    output_directory: str = Field(min_length=1)


class JebItemInput(AnalysisInput):
    item: str = Field(min_length=1)
    max_bytes: int = Field(default=64_000, ge=0, le=10_000_000)


class FridaSessionInput(_Input):
    session_id: str | None = None
    device: str | None = None
    target: str | int | None = None
    spawn: bool = False
    source: str | None = None
    name: str | None = None
    duration: float = 2.0


class NativeToolInput(AnalysisInput):
    address: str | None = None
    name: str | None = None
    comment: str | None = None
    text: str | None = None
    function: str = "main"
    query: str | None = None
    limit: int = 200
    count: int = 64
    delta: int = 1
    assignments: list[dict[str, Any]] | None = None


class DebugSessionInput(_Input):
    session_id: str | None = None
    command: str | None = None
    commands: list[str] | None = None
    args: list[str] | None = None
    timeout: float | None = None


class VerifyReconstructionInput(_Input):
    ledger: dict[str, Any]


class VerifyUnknownInput(_Input):
    unknown_id: str = Field(min_length=1)


class BatchDecompileInput(_Input):
    functions: list[str] = Field(min_length=1)
    max_bytes_per_function: int = Field(default=64_000, ge=0, le=10_000_000)


class CallGraphInput(_Input):
    limit: int = Field(default=50, ge=1, le=1000)


class CallPathInput(_Input):
    from_function: str = Field(min_length=1)
    to_function: str = Field(min_length=1)
    limit: int = Field(default=50, ge=1, le=1000)


class TraceFeatureInput(_Input):
    feature: str = Field(min_length=1)


class TraceValuesInput(_Input):
    query: str = Field(min_length=1)


class GhidraAnalyzeInput(AnalysisInput):
    language: str | None = Field(
        default=None, description="Ghidra language id, e.g. 68000:BE:32:default."
    )
    compiler: str | None = Field(default=None, description="Ghidra compiler specification id.")


class ApktoolResourcesInput(AnalysisInput):
    include_strings: bool = True
    string_tables_only: bool = False
    locale: str | None = None
    locales: list[str] | None = None


class AndroidDeepInput(AnalysisInput):
    class_name: str | None = None
    method: str | None = None
    query: str | None = None
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=200, ge=1, le=10_000)


class WebMcpInvokeInput(_Input):
    url: str = Field(min_length=1)
    name: str = Field(min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)


class WebToolInput(_Input):
    url: str | None = None
    endpoint: str | None = None
    output: str | None = None
    left: str | None = None
    right: str | None = None
    source_url: str | None = None
    symbol: str | None = None
    query: str | None = None
    path: str | None = None
    steps: list[dict[str, Any]] | None = None
    duration: float = 3.0
    full_page: bool = False
    capture_bodies: bool = False
    selector: str | None = None
    value: str | None = None


class EngineEndpointInput(_Input):
    pass


class RecordedCrashInput(AnalysisInput):
    executable: str = Field(
        min_length=1, description="Path to the executable that produced the core."
    )


class DoctorInput(_Input):
    pass


@dataclass(frozen=True)
class ToolContract:
    name: str
    description: str
    input_model: type[BaseModel]
    operation: str | None
    requires_target: bool = False
    returns_evidence: bool = True


def _analysis_contract(operation: str, description: str, model: type[BaseModel]) -> ToolContract:
    return ToolContract(
        name=operation.replace("_", "-") if False else operation,
        description=description,
        input_model=model,
        operation=operation,
        requires_target=True,
    )


TOOL_CONTRACTS: tuple[ToolContract, ...] = (
    ToolContract(
        name="open_binary",
        description="Open a local target and bind a provider for analysis.",
        input_model=OpenBinaryInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="close_binary",
        description="Close the active target and release provider resources.",
        input_model=CloseBinaryInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="binary_session",
        description="Report the active session, tools, and providers.",
        input_model=SessionInput,
        operation=None,
        returns_evidence=False,
    ),
    _analysis_contract("inspect_byte_entropy", "File and block byte entropy.", AnalysisInput),
    _analysis_contract("read_bytes", "Read file-backed bytes at an address.", AnalysisInput),
    _analysis_contract("search_bytes", "Search file-backed bytes with wildcards.", AnalysisInput),
    _analysis_contract("address_to_file_offset", "Map an address to a file offset.", AnalysisInput),
    _analysis_contract(
        "inspect_binary_layout",
        "Sections, segments, symbols and mitigation candidates for ELF/PE/Mach-O.",
        AnalysisInput,
    ),
    _analysis_contract(
        "inspect_elf_notes",
        "ELF PT_NOTE and SHT_NOTE tables.",
        AnalysisInput,
    ),
    _analysis_contract(
        "inspect_go_binary",
        "Embedded Go compiler version, modules and build settings.",
        AnalysisInput,
    ),
    _analysis_contract(
        "inspect_rust_binary",
        "cargo-auditable dependency inventory embedded in the binary.",
        AnalysisInput,
    ),
    _analysis_contract(
        "inspect_managed_artifact",
        "Static .NET/CLI metadata identity and table counts.",
        ManagedArtifactInput,
    ),
    _analysis_contract(
        "inspect_managed_members",
        "Managed assembly member names (types/methods) and counts.",
        ManagedMembersInput,
    ),
    _analysis_contract(
        "disassemble_managed_method",
        "Disassemble one managed method's IL body.",
        MethodInput,
    ),
    _analysis_contract(
        "inspect_network_capture",
        "HAR/SAZ capture requests, hosts and status.",
        PagedAnalysisInput,
    ),
    _analysis_contract(
        "inspect_harmony_package", "HarmonyOS HAP package facts and entry hashes.", AnalysisInput
    ),
    _analysis_contract(
        "analyze_javascript_application",
        "JavaScript/Electron module graph and IPC boundaries.",
        JavaScriptInput,
    ),
    _analysis_contract(
        "inspect_keyed_archive", "NSKeyedArchiver class and object inventory.", AnalysisInput
    ),
    _analysis_contract("inspect_pe_resources", "PE resource types and counts.", AnalysisInput),
    _analysis_contract(
        "inspect_pe_certificates",
        "PE Authenticode certificate-table entries.",
        AnalysisInput,
    ),
    _analysis_contract(
        "inspect_native_exports",
        "PE/ELF export names, ordinals and addresses.",
        AnalysisInput,
    ),
    _analysis_contract(
        "inspect_javascript_webmcp",
        "Static JavaScript WebMCP declaration candidates.",
        PagedAnalysisInput,
    ),
    _analysis_contract(
        "inspect_javascript_source_maps",
        "Static JavaScript source-map inventory.",
        PagedAnalysisInput,
    ),
    _analysis_contract(
        "inspect_javascript_routes",
        "Static JavaScript route candidates.",
        PagedAnalysisInput,
    ),
    _analysis_contract(
        "inspect_javascript_dataflow",
        "Static JavaScript storage/DOM source-to-sink flows.",
        PagedAnalysisInput,
    ),
    _analysis_contract(
        "inspect_asset_catalog",
        "Apple asset catalog (Assets.car) header and embedded strings.",
        AnalysisInput,
    ),
    _analysis_contract(
        "capture_live_network",
        "Capture live HTTP(S) traffic through a caller-supplied mitmproxy.",
        AnalysisInput,
    ),
    _analysis_contract(
        "hopper_analyze", "Hopper document overview via the running bridge.", AnalysisInput
    ),
    _analysis_contract(
        "hopper_function", "Hopper function inventory via the running bridge.", FunctionInput
    ),
    _analysis_contract(
        "hopper_decompile", "Hopper pseudocode via the running bridge.", DecompileInput
    ),
    _analysis_contract("hopper_xrefs", "Hopper references via the running bridge.", XrefsInput),
    _analysis_contract(
        "inspect_sqlite_database", "Tables, columns, indexes, views and triggers.", SqliteInput
    ),
    _analysis_contract(
        "inspect_artifact",
        "File inventory and digests for zip/apk/asar/tar/directory.",
        PagedAnalysisInput,
    ),
    _analysis_contract(
        "inspect_android_package",
        "APK inventory, DEX facts and manifest package facts.",
        PagedAnalysisInput,
    ),
    _analysis_contract(
        "identify_flutter_build", "Flutter AOT snapshot fingerprint per ABI.", AnalysisInput
    ),
    _analysis_contract(
        "inspect_erlang_beam",
        "Erlang BEAM IFF chunks and atoms.",
        AnalysisInput,
    ),
    _analysis_contract(
        "inspect_wasm_artifact",
        "WASM validation, sections and (with WABT) decoded WAT.",
        AnalysisInput,
    ),
    _analysis_contract(
        "inspect_evm_interface", "EVM dispatch selectors via evmole (optional).", AnalysisInput
    ),
    _analysis_contract(
        "inspect_pcap_capture",
        "Saved capture protocol hierarchy and endpoints (tshark).",
        AnalysisInput,
    ),
    _analysis_contract(
        "inspect_firmware_regions", "Firmware regions via binwalk (caller-supplied).", AnalysisInput
    ),
    _analysis_contract(
        "import_reference_source",
        "Inventory a local source tree (files, sizes, digests, languages).",
        AnalysisInput,
    ),
    _analysis_contract(
        "inspect_plist", "Property list (XML/binary) top-level projection.", AnalysisInput
    ),
    _analysis_contract(
        "inspect_with_objdump", "File/section headers via GNU objdump.", AnalysisInput
    ),
    _analysis_contract("instructions", "Disassembly instructions.", InstructionsInput),
    _analysis_contract("analyze", "Provider overview analysis.", AnalysisInput),
    _analysis_contract("function", "List/select functions.", FunctionInput),
    _analysis_contract("decompile", "Pseudocode for a function.", DecompileInput),
    _analysis_contract(
        "decompile_managed_csharp",
        "Optional C# decompilation through ilspycmd.",
        ManagedCSharpInput,
    ),
    _analysis_contract("search", "Search within the target.", SearchInput),
    _analysis_contract("xrefs", "Cross-references to an address or function.", XrefsInput),
    ToolContract(
        name="record_unknown",
        description="Record an unresolved investigation question (unknown).",
        input_model=RecordUnknownToolInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="update_unknown",
        description="Update an unknown's status/resolution.",
        input_model=UpdateUnknownToolInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="list_unknowns",
        description="List recorded unknowns (current revisions).",
        input_model=SessionInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="snapshot_export",
        description="Open a target and export an analysis snapshot to a file.",
        input_model=SnapshotExportToolInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="snapshot_import",
        description="Import a saved analysis snapshot for a target.",
        input_model=SnapshotImportToolInput,
        operation=None,
        returns_evidence=False,
    ),
    _analysis_contract(
        "inspect_electron_fuses", "Electron fuse-wire security posture.", AnalysisInput
    ),
    _analysis_contract(
        "inspect_entitlements", "Entitlements plist key/value inventory.", AnalysisInput
    ),
    _analysis_contract(
        "inspect_interface_builder",
        "Compiled Interface Builder archive inventory.",
        AnalysisInput,
    ),
    _analysis_contract(
        "inspect_signal_capture", "VCD signal inventory and transition counts.", AnalysisInput
    ),
    _analysis_contract(
        "decode_uart_capture", "Decode 8N1 UART from a VCD signal.", SignalDecodeInput
    ),
    _analysis_contract(
        "inspect_crash_dump", "Structured GDB/pwndbg crash-dump summary.", AnalysisInput
    ),
    ToolContract(
        name="compare_network_captures",
        description="Compare two HAR/SAZ captures by request set.",
        input_model=CompareCapturesInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="compare_web_captures",
        description="Compare two web network captures by request set.",
        input_model=CompareCapturesInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="compare_managed_members",
        description="Compare the member sets of two managed assemblies.",
        input_model=CompareCapturesInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="build_reconstruction_obligation_ledger",
        description="Build a reconstruction obligation ledger and its coverage.",
        input_model=BuildLedgerInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="evaluate_reconstruction_coverage",
        description="Evaluate coverage/gaps from a reconstruction ledger.",
        input_model=EvaluateCoverageInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="observe_web_page",
        description="Observe a page's title, final URL and script count via playwright.",
        input_model=ObserveWebPageInput,
        operation="observe_web_page",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="inspect_cdp_targets",
        description="List Chrome DevTools Protocol targets from a running runtime.",
        input_model=CdpEndpointInput,
        operation="inspect_cdp_targets",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="capture_cdp_network",
        description="Capture CDP network request metadata for a bounded duration.",
        input_model=CaptureCdpInput,
        operation="capture_cdp_network",
        requires_target=False,
        returns_evidence=False,
    ),
    _analysis_contract(
        "decode_android_resources",
        "Decode APK resources with apktool, optionally projecting string tables.",
        ApktoolResourcesInput,
    ),
    _analysis_contract("decode_android_smali", "Full apktool smali inventory.", AnalysisInput),
    _analysis_contract(
        "decompile_android_apk", "Decompile an APK to Java with JADX.", PagedAnalysisInput
    ),
    _analysis_contract(
        "decompile_android_class", "Decompile one class with JADX.", AndroidClassInput
    ),
    _analysis_contract(
        "decode_signal_recording", "Decode a logic-signal recording with sigrok.", AnalysisInput
    ),
    _analysis_contract("kuna_decompile", "Decompile a function with Kuna.", DecompileInput),
    _analysis_contract(
        "ghidra_analyze", "Ghidra overview via pyhidra/pyghidra.", GhidraAnalyzeInput
    ),
    _analysis_contract("ghidra_function", "Ghidra function inventory.", FunctionInput),
    _analysis_contract("ghidra_decompile", "Ghidra pseudocode.", DecompileInput),
    _analysis_contract("ida_analyze", "IDA overview via the running service.", AnalysisInput),
    _analysis_contract("ida_function", "IDA function inventory.", FunctionInput),
    _analysis_contract("ida_decompile", "IDA pseudocode.", DecompileInput),
    _analysis_contract("ida_xrefs", "IDA cross-references.", XrefsInput),
    _analysis_contract("jeb_analyze", "JEB overview via the running service.", AnalysisInput),
    _analysis_contract("jeb_function", "JEB function inventory.", FunctionInput),
    _analysis_contract("jeb_decompile", "JEB pseudocode.", DecompileInput),
    _analysis_contract(
        "inspect_recorded_crash", "Registers/signal from a recorded core.", RecordedCrashInput
    ),
    ToolContract(
        name="list_adb_devices",
        description="List attached ADB devices.",
        input_model=SessionInput,
        operation="list_adb_devices",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="list_adb_packages",
        description="List installed packages on the attached device.",
        input_model=SessionInput,
        operation="list_adb_packages",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="android_app_info",
        description="Dump package facts for one Android package.",
        input_model=AndroidAppInfoInput,
        operation="android_app_info",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="adb_shell",
        description="Run a bounded command through 'adb shell'.",
        input_model=AdbShellInput,
        operation="adb_shell",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="list_frida_devices",
        description="List Frida devices.",
        input_model=SessionInput,
        operation="list_frida_devices",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="list_frida_applications",
        description="List applications on a Frida device.",
        input_model=FridaDeviceInput,
        operation="list_frida_applications",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="list_frida_processes",
        description="List processes on a Frida device.",
        input_model=FridaDeviceInput,
        operation="list_frida_processes",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="ida_inspect_provider",
        description="Probe the configured IDA service endpoint.",
        input_model=EngineEndpointInput,
        operation="ida_inspect_provider",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="jeb_inspect_provider",
        description="Probe the configured JEB service endpoint.",
        input_model=EngineEndpointInput,
        operation="jeb_inspect_provider",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="inspect_adb_client",
        description="Inspect the caller-selected adb binary and version.",
        input_model=AdbToolInput,
        operation="inspect_adb_client",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="inspect_adb_device",
        description="Inspect one device's build identity via getprop.",
        input_model=AdbToolInput,
        operation="inspect_adb_device",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="pull_adb_package",
        description="Pull every APK of an installed package.",
        input_model=AdbToolInput,
        operation="pull_adb_package",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="read_adb_logcat",
        description="Read the most recent logcat lines.",
        input_model=AdbToolInput,
        operation="read_adb_logcat",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="inspect_adb_package",
        description="Dump package facts for one installed package.",
        input_model=AdbToolInput,
        operation="inspect_adb_package",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="pull_adb_file",
        description="Pull one absolute device file.",
        input_model=AdbToolInput,
        operation="pull_adb_file",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="push_adb_file",
        description="Push a local file to an absolute device path.",
        input_model=AdbToolInput,
        operation="push_adb_file",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="capture_adb_screen",
        description="Capture a PNG screenshot from the device.",
        input_model=AdbToolInput,
        operation="capture_adb_screen",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="list_adb_processes",
        description="List device processes (ps -A).",
        input_model=AdbToolInput,
        operation="list_adb_processes",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="list_adb_directory",
        description="List one absolute device directory.",
        input_model=AdbToolInput,
        operation="list_adb_directory",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="list_adb_features",
        description="List device package-manager features.",
        input_model=AdbToolInput,
        operation="list_adb_features",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="list_adb_services",
        description="List device services.",
        input_model=AdbToolInput,
        operation="list_adb_services",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="inspect_adb_display",
        description="Dump display state.",
        input_model=AdbToolInput,
        operation="inspect_adb_display",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="inspect_adb_window",
        description="Dump window state.",
        input_model=AdbToolInput,
        operation="inspect_adb_window",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="read_adb_setting",
        description="Read one settings namespace key.",
        input_model=AdbToolInput,
        operation="read_adb_setting",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="collect_adb_bugreport",
        description="Collect a device bugreport archive.",
        input_model=AdbToolInput,
        operation="collect_adb_bugreport",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="resolve_adb_packages",
        description="Resolve packages by case-insensitive substring.",
        input_model=AdbToolInput,
        operation="resolve_adb_packages",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="install_adb_package",
        description="Install a local APK.",
        input_model=AdbToolInput,
        operation="install_adb_package",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="uninstall_adb_package",
        description="Uninstall an installed package.",
        input_model=AdbToolInput,
        operation="uninstall_adb_package",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="start_adb_app",
        description="Start an app's launcher activity.",
        input_model=AdbToolInput,
        operation="start_adb_app",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="start_adb_activity",
        description="Start an activity with an intent.",
        input_model=AdbToolInput,
        operation="start_adb_activity",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="stop_adb_app",
        description="Force-stop an app.",
        input_model=AdbToolInput,
        operation="stop_adb_app",
        requires_target=False,
        returns_evidence=False,
    ),
    _analysis_contract(
        "inspect_packet_fields", "Per-packet fields for a saved capture.", PacketFieldsInput
    ),
    _analysis_contract(
        "inspect_packet_capture", "Saved capture summary and endpoints.", AnalysisInput
    ),
    ToolContract(
        name="inspect_pcap_client",
        description="Inspect the caller-selected tshark client.",
        input_model=SessionInput,
        operation="inspect_pcap_client",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="inspect_signal_decoders",
        description="List available sigrok signal decoders.",
        input_model=SessionInput,
        operation="inspect_signal_decoders",
        requires_target=False,
        returns_evidence=False,
    ),
    _analysis_contract(
        "extract_firmware", "Extract firmware regions to files.", FirmwareExtractInput
    ),
    ToolContract(
        name="inspect_jeb_client",
        description="Inspect the configured JEB service.",
        input_model=EngineEndpointInput,
        operation="inspect_jeb_client",
        requires_target=False,
        returns_evidence=False,
    ),
    _analysis_contract("open_jeb_project", "Open a project in JEB.", AnalysisInput),
    _analysis_contract("list_jeb_units", "List JEB project units.", AnalysisInput),
    _analysis_contract("decompile_jeb_item", "Decompile one JEB unit.", JebItemInput),
    ToolContract(
        name="start_frida_session",
        description="Start a Frida session on a process.",
        input_model=FridaSessionInput,
        operation="start_frida_session",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="frida_session_status",
        description="Report a Frida session.",
        input_model=FridaSessionInput,
        operation="frida_session_status",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="load_frida_script",
        description="Load a script into a Frida session.",
        input_model=FridaSessionInput,
        operation="load_frida_script",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="unload_frida_script",
        description="Unload a Frida script.",
        input_model=FridaSessionInput,
        operation="unload_frida_script",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="resume_frida_session",
        description="Resume a spawned Frida session.",
        input_model=FridaSessionInput,
        operation="resume_frida_session",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="close_frida_session",
        description="Close a Frida session.",
        input_model=FridaSessionInput,
        operation="close_frida_session",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="instrument_with_frida",
        description="Attach, run a script briefly, and collect messages.",
        input_model=FridaSessionInput,
        operation="instrument_with_frida",
        requires_target=False,
        returns_evidence=False,
    ),
    _analysis_contract("current_address", "Current navigation address.", NativeToolInput),
    _analysis_contract("goto_address", "Seek to an address.", NativeToolInput),
    _analysis_contract("next_address", "Advance the current address.", NativeToolInput),
    _analysis_contract("prev_address", "Return to the previous address.", NativeToolInput),
    _analysis_contract("current_document", "Current document identity.", NativeToolInput),
    _analysis_contract(
        "current_procedure", "Procedure containing the current address.", NativeToolInput
    ),
    _analysis_contract("list_documents", "List open documents.", NativeToolInput),
    _analysis_contract("list_segments", "List segments.", NativeToolInput),
    _analysis_contract("list_strings", "List strings.", NativeToolInput),
    _analysis_contract("list_names", "List names/flags.", NativeToolInput),
    _analysis_contract("list_procedures", "List procedures.", NativeToolInput),
    _analysis_contract("list_bookmarks", "List bookmarks.", NativeToolInput),
    _analysis_contract("set_bookmark", "Set a bookmark.", NativeToolInput),
    _analysis_contract("unset_bookmark", "Remove a bookmark.", NativeToolInput),
    _analysis_contract(
        "get_navigation_context", "Navigation context at an address.", NativeToolInput
    ),
    _analysis_contract(
        "inspect_address_context", "Instruction/function/xref context.", NativeToolInput
    ),
    _analysis_contract("address_name", "Name at an address.", NativeToolInput),
    _analysis_contract("comment", "Comment at an address.", NativeToolInput),
    _analysis_contract("inline_comment", "Inline comment at an address.", NativeToolInput),
    _analysis_contract("set_address_name", "Rename a function at an address.", NativeToolInput),
    _analysis_contract("set_addresses_names", "Apply multiple address renames.", NativeToolInput),
    _analysis_contract("set_comment", "Set a comment at an address.", NativeToolInput),
    _analysis_contract(
        "set_inline_comment", "Set an inline comment at an address.", NativeToolInput
    ),
    _analysis_contract(
        "annotate_native_function", "Rename and/or comment one function.", NativeToolInput
    ),
    _analysis_contract("procedure_address", "Entry address of a procedure.", NativeToolInput),
    _analysis_contract("procedure_assembly", "Disassembly of a procedure.", NativeToolInput),
    _analysis_contract("procedure_callees", "Callees of a procedure.", NativeToolInput),
    _analysis_contract("procedure_callers", "Callers of a procedure.", NativeToolInput),
    _analysis_contract("procedure_info", "Procedure metadata.", NativeToolInput),
    _analysis_contract("procedure_pseudo_code", "Pseudocode for a procedure.", DecompileInput),
    _analysis_contract("procedure_references", "Callers and callees.", NativeToolInput),
    _analysis_contract(
        "resolve_containing_procedure",
        "Resolve the procedure containing an address.",
        NativeToolInput,
    ),
    _analysis_contract(
        "resolve_native_call_targets", "Resolve call targets at an address.", NativeToolInput
    ),
    _analysis_contract(
        "read_function_instructions", "Instructions for a function/address.", NativeToolInput
    ),
    _analysis_contract("search_procedures", "Search procedure names.", NativeToolInput),
    _analysis_contract("search_strings", "Search strings.", NativeToolInput),
    _analysis_contract(
        "find_xrefs_to_name", "Cross-references to a named symbol.", NativeToolInput
    ),
    _analysis_contract("inspect_native_data_type", "Recovered types.", NativeToolInput),
    _analysis_contract(
        "inspect_native_instruction", "Decoded instruction at an address.", NativeToolInput
    ),
    _analysis_contract(
        "inspect_native_load_image", "Loaded image verification facts.", NativeToolInput
    ),
    _analysis_contract("inspect_native_api", "Imported API inventory.", NativeToolInput),
    _analysis_contract("analyze_swift_types", "Objective-C/Swift metadata.", NativeToolInput),
    _analysis_contract("get_objc_classes", "Objective-C classes.", NativeToolInput),
    _analysis_contract("get_objc_protocols", "Objective-C protocols.", NativeToolInput),
    _analysis_contract("start_gdb_session", "Start a GDB session.", DebugSessionInput),
    ToolContract(
        name="gdb_session_status",
        description="Report a GDB session.",
        input_model=DebugSessionInput,
        operation="gdb_session_status",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="close_gdb_session",
        description="Close a GDB session.",
        input_model=DebugSessionInput,
        operation="close_gdb_session",
        requires_target=False,
        returns_evidence=False,
    ),
    _analysis_contract("gdb_console", "Run GDB batch commands.", DebugSessionInput),
    _analysis_contract(
        "start_rizin_debug_session", "Start a Rizin debug session.", DebugSessionInput
    ),
    ToolContract(
        name="rizin_debug_session_status",
        description="Report a Rizin debug session.",
        input_model=DebugSessionInput,
        operation="rizin_debug_session_status",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="close_rizin_debug_session",
        description="Close a Rizin debug session.",
        input_model=DebugSessionInput,
        operation="close_rizin_debug_session",
        requires_target=False,
        returns_evidence=False,
    ),
    _analysis_contract("rizin_debug_command", "Run a Rizin debug command.", DebugSessionInput),
    _analysis_contract("execute_rizin_command", "Run a Rizin command.", DebugSessionInput),
    ToolContract(
        name="list_cutter_sessions",
        description="List Cutter bridge sessions.",
        input_model=DebugSessionInput,
        operation="list_cutter_sessions",
        requires_target=False,
        returns_evidence=False,
    ),
    _analysis_contract(
        "cutter_command", "Run a command through the Cutter bridge.", DebugSessionInput
    ),
    ToolContract(
        name="inspect_managed_native_boundaries",
        description="Inspect managed P/Invoke and native implementation declarations.",
        input_model=ManagedPathInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="verify_managed_native_boundaries",
        description="Verify declared managed native boundaries.",
        input_model=VerifyManagedBoundariesInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="import_managed_reconstruction",
        description="Import a managed reconstruction ledger.",
        input_model=ManagedJsonInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="compare_application_versions",
        description="Compare two static JavaScript application graphs.",
        input_model=TwoPathsInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="compare_source_to_bundle",
        description="Compare a source graph with a shipped application graph.",
        input_model=TwoPathsInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="trace_application_feature",
        description="Trace a feature through a static JavaScript application graph.",
        input_model=FeatureInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="trace_javascript_semantics",
        description="Trace static JavaScript module semantics.",
        input_model=NodeTraceInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="compare_javascript_export_shapes",
        description="Compare static JavaScript module/export shape evidence.",
        input_model=ExportShapeInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="invoke_webmcp_tool",
        description="Explicitly invoke a registered WebMCP tool.",
        input_model=WebMcpInvokeInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="match_native_functions",
        description="Match exact native export names between two binaries.",
        input_model=MatchNativeInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="compare_wasm_interfaces",
        description="Compare WASM import/export declarations.",
        input_model=CompareWasmInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="project_android_application_graph",
        description="Project an Android application graph.",
        input_model=ManagedPathInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="project_apple_application_graph",
        description="Project an Apple application graph.",
        input_model=ManagedPathInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="project_harmony_application_graph",
        description="Project a Harmony application graph.",
        input_model=ManagedPathInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="project_managed_application_graph",
        description="Project a managed application graph.",
        input_model=ManagedPathInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="get_evidence_bundle",
        description="Return a summary of the session Evidence bundle (or the full bundle).",
        input_model=GetEvidenceBundleInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="verify_reconstruction",
        description="Verify a reconstruction ledger.",
        input_model=VerifyReconstructionInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="verify_unknown_resolution",
        description="Verify an unknown's resolution status.",
        input_model=VerifyUnknownInput,
        operation=None,
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="compare_bundles",
        description="Compare two Evidence bundles.",
        input_model=CompareInput,
        operation=None,
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="compare_functions",
        description="Compare function inventories from two Evidence files.",
        input_model=CompareInput,
        operation=None,
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="compare_process_captures",
        description="Compare two process captures.",
        input_model=CompareInput,
        operation=None,
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="correlate_static_and_runtime",
        description="Correlate static and runtime Evidence operations.",
        input_model=CompareInput,
        operation=None,
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="find_changed_behavior",
        description="Find changed Evidence between two bundles.",
        input_model=CompareInput,
        operation=None,
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="batch_decompile",
        description="Decompile multiple functions.",
        input_model=BatchDecompileInput,
        operation=None,
        requires_target=True,
        returns_evidence=False,
    ),
    ToolContract(
        name="get_call_graph",
        description="Build a function call graph.",
        input_model=CallGraphInput,
        operation=None,
        requires_target=True,
        returns_evidence=False,
    ),
    ToolContract(
        name="build_call_path",
        description="Find a call path between two functions.",
        input_model=CallPathInput,
        operation=None,
        requires_target=True,
        returns_evidence=False,
    ),
    ToolContract(
        name="trace_call_path",
        description="Trace a call path between two functions.",
        input_model=CallPathInput,
        operation=None,
        requires_target=True,
        returns_evidence=False,
    ),
    ToolContract(
        name="trace_feature",
        description="Trace a feature across strings, procedures and xrefs.",
        input_model=TraceFeatureInput,
        operation=None,
        requires_target=True,
        returns_evidence=False,
    ),
    ToolContract(
        name="trace_native_values",
        description="Trace values across strings and matches.",
        input_model=TraceValuesInput,
        operation=None,
        requires_target=True,
        returns_evidence=False,
    ),
    ToolContract(
        name="inspect_apktool_client",
        description="Inspect the caller-selected apktool binary.",
        input_model=SessionInput,
        operation="inspect_apktool_client",
        requires_target=False,
        returns_evidence=False,
    ),
    _analysis_contract("inspect_dart_aot", "Static Dart AOT snapshot facts.", AnalysisInput),
    _analysis_contract(
        "search_android_classes", "Search decompiled Android classes.", AndroidDeepInput
    ),
    _analysis_contract(
        "inspect_android_class", "Inspect one decompiled Android class.", AndroidDeepInput
    ),
    _analysis_contract("inspect_android_method", "Inspect one Android method.", AndroidDeepInput),
    _analysis_contract(
        "trace_android_references", "Search references across decompiled sources.", AndroidDeepInput
    ),
    ToolContract(
        name="list_browser_targets",
        description="List browser CDP targets.",
        input_model=WebToolInput,
        operation="list_browser_targets",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="list_electron_targets",
        description="List Electron CDP targets.",
        input_model=WebToolInput,
        operation="list_electron_targets",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="list_javascript_runtime_targets",
        description="List JavaScript runtime targets.",
        input_model=WebToolInput,
        operation="list_javascript_runtime_targets",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="inspect_web_page",
        description="Inspect a page's title, scripts, forms and meta.",
        input_model=WebToolInput,
        operation="inspect_web_page",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="inspect_web_event_listeners",
        description="Inspect inline handlers and native listener source locations.",
        input_model=WebToolInput,
        operation="inspect_web_event_listeners",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="observe_web_execution",
        description="Observe console output and requests.",
        input_model=WebToolInput,
        operation="observe_web_execution",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="observe_web_session",
        description="Observe cookies and web storage.",
        input_model=WebToolInput,
        operation="observe_web_session",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="capture_web_screenshot",
        description="Capture a page screenshot.",
        input_model=WebToolInput,
        operation="capture_web_screenshot",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="compare_web_screenshots",
        description="Compare two screenshots.",
        input_model=WebToolInput,
        operation="compare_web_screenshots",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="capture_browser_scenario",
        description="Run a browser scenario.",
        input_model=WebToolInput,
        operation="capture_browser_scenario",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="capture_electron_scenario",
        description="Run an Electron/CDP scenario.",
        input_model=WebToolInput,
        operation="capture_electron_scenario",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="inspect_electron_page",
        description="Inspect an Electron page target.",
        input_model=WebToolInput,
        operation="inspect_electron_page",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="observe_javascript_runtime",
        description="List runtime targets.",
        input_model=WebToolInput,
        operation="observe_javascript_runtime",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="reconcile_javascript_runtime",
        description="Reconcile runtime target sets.",
        input_model=WebToolInput,
        operation="reconcile_javascript_runtime",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="analyze_web_bundle",
        description="Analyze a local JavaScript bundle.",
        input_model=WebToolInput,
        operation="analyze_web_bundle",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="export_web_scripts",
        description="Export page scripts to files.",
        input_model=WebToolInput,
        operation="export_web_scripts",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="recover_javascript_sources",
        description="Recover sources from source maps.",
        input_model=WebToolInput,
        operation="recover_javascript_sources",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="trace_web_module_imports",
        description="Trace module imports across scripts.",
        input_model=WebToolInput,
        operation="trace_web_module_imports",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="trace_web_source_location",
        description="Find a symbol in a source file.",
        input_model=WebToolInput,
        operation="trace_web_source_location",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="discover_webmcp_tools",
        description="Discover WebMCP declarations.",
        input_model=WebToolInput,
        operation="discover_webmcp_tools",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="trace_native_ui_action",
        description="Trace a native UI action.",
        input_model=WebToolInput,
        operation="trace_native_ui_action",
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="binary_overview",
        description="Alias for the provider overview analysis.",
        input_model=AnalysisInput,
        operation=None,
        requires_target=True,
        returns_evidence=True,
    ),
    ToolContract(
        name="analyze_function",
        description="Alias for function inventory/selection.",
        input_model=FunctionInput,
        operation=None,
        requires_target=True,
        returns_evidence=True,
    ),
    ToolContract(
        name="capture_process_scenario",
        description="Alias for bounded process capture.",
        input_model=CaptureInput,
        operation=None,
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="compare_artifacts",
        description="Alias for comparing saved Evidence records.",
        input_model=CompareInput,
        operation=None,
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="export_evidence_bundle",
        description="Alias for Evidence bundle export.",
        input_model=EvidenceExportInput,
        operation=None,
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="import_evidence_bundle",
        description="Alias for Evidence bundle import.",
        input_model=EvidenceImportInput,
        operation=None,
        requires_target=False,
        returns_evidence=False,
    ),
    ToolContract(
        name="inspect_web_network_capture",
        description="Alias for HAR/SAZ capture inspection.",
        input_model=AnalysisInput,
        operation=None,
        requires_target=True,
        returns_evidence=True,
    ),
    ToolContract(
        name="compare_evidence",
        description="Compare two saved Evidence records.",
        input_model=CompareInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="capture_process",
        description="Run a command and capture bounded stdout/stderr, exit code and timeout.",
        input_model=CaptureInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="doctor",
        description="Report provider and external-tool readiness.",
        input_model=DoctorInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="setup",
        description="Plan or write an MCP client registration for the REA-Python server.",
        input_model=SetupInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="update",
        description="Report the installed version and update guidance.",
        input_model=SessionInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="providers",
        description="List configured analysis providers and their operations.",
        input_model=ProvidersInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="evidence_export",
        description="Export the session Evidence bundle to a JSON file.",
        input_model=EvidenceExportInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="evidence_import",
        description="Import an Evidence bundle file into the session.",
        input_model=EvidenceImportInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="inspect_analysis_view",
        description="Project a saved Evidence record or bundle into a summary.",
        input_model=AnalysisViewInput,
        operation=None,
        returns_evidence=False,
    ),
)

CONTRACTS_BY_NAME: dict[str, ToolContract] = {
    contract.name: contract for contract in TOOL_CONTRACTS
}


def analysis_operations(providers: list[AnalysisProvider]) -> list[str]:
    operations: set[str] = set()
    for provider in providers:
        operations.update(provider.operation_names())
    return sorted(operations)


def operation_description(providers: list[AnalysisProvider], operation: str) -> str | None:
    for provider in providers:
        for descriptor in provider.capabilities():
            if descriptor.operation == operation:
                return None
    return None


def contract_for_operation(operation: str) -> ToolContract | None:
    for contract in TOOL_CONTRACTS:
        if contract.operation == operation:
            return contract
    return None


def contract_input_example(contract: ToolContract) -> dict[str, Any]:
    return contract.input_model().model_dump(exclude_none=True)


__all__ = [
    "CONTRACTS_BY_NAME",
    "TOOL_CONTRACTS",
    "AnalysisInput",
    "AnalysisViewInput",
    "CloseBinaryInput",
    "EvidenceExportInput",
    "EvidenceImportInput",
    "OpenBinaryInput",
    "ProvidersInput",
    "SessionInput",
    "SqliteInput",
    "ToolContract",
    "analysis_operations",
    "contract_for_operation",
    "contract_input_example",
]
