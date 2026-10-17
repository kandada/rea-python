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


class AnalysisInput(_Input):
    path: str | None = Field(
        default=None, description="Optional target path; uses the open target otherwise."
    )


class SqliteInput(AnalysisInput):
    table: str | None = Field(default=None, description="Read a bounded sample from this table.")
    row_limit: int = Field(default=20, ge=0, le=1000)


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
    view: Literal["summary", "record", "page"] = "summary"
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=64, ge=1, le=1000)


class SetupInput(_Input):
    path: str | None = Field(default=None, description="Optional client config path to write.")
    overwrite: bool = False


class MethodInput(AnalysisInput):
    method: str = Field(min_length=1)
    type: str | None = None


class FunctionInput(AnalysisInput):
    function: str = "main"
    limit: int = Field(default=200, ge=1, le=10000)


class SearchInput(AnalysisInput):
    query: str = Field(min_length=1)
    limit: int = Field(default=100, ge=1, le=10000)


class DecompileInput(AnalysisInput):
    function: str = "main"


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
    _analysis_contract(
        "inspect_binary_layout",
        "Sections, segments, symbols and mitigation candidates for ELF/PE/Mach-O.",
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
        AnalysisInput,
    ),
    _analysis_contract(
        "inspect_managed_members",
        "Managed assembly member names (types/methods) and counts.",
        AnalysisInput,
    ),
    _analysis_contract(
        "disassemble_managed_method",
        "Disassemble one managed method's IL body.",
        MethodInput,
    ),
    _analysis_contract(
        "inspect_network_capture", "HAR/SAZ capture requests, hosts and status.", AnalysisInput
    ),
    _analysis_contract(
        "inspect_harmony_package", "HarmonyOS HAP package facts and entry hashes.", AnalysisInput
    ),
    _analysis_contract(
        "analyze_javascript_application",
        "JavaScript/Electron module graph and IPC boundaries.",
        AnalysisInput,
    ),
    _analysis_contract(
        "inspect_keyed_archive", "NSKeyedArchiver class and object inventory.", AnalysisInput
    ),
    _analysis_contract("inspect_pe_resources", "PE resource types and counts.", AnalysisInput),
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
        AnalysisInput,
    ),
    _analysis_contract(
        "inspect_android_package",
        "APK inventory, DEX facts and manifest package facts.",
        AnalysisInput,
    ),
    _analysis_contract(
        "identify_flutter_build", "Flutter AOT snapshot fingerprint per ABI.", AnalysisInput
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
    _analysis_contract("search", "Search within the target.", SearchInput),
    _analysis_contract("xrefs", "Cross-references to an address or function.", XrefsInput),
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
        name="evidence-export",
        description="Export the session Evidence bundle to a JSON file.",
        input_model=EvidenceExportInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="evidence-import",
        description="Import an Evidence bundle file into the session.",
        input_model=EvidenceImportInput,
        operation=None,
        returns_evidence=False,
    ),
    ToolContract(
        name="inspect-analysis-view",
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
