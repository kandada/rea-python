import pytest
from pydantic import ValidationError

from rea_mcp.composition.factories import build_providers
from rea_mcp.contracts.tool_contracts import (
    CONTRACTS_BY_NAME,
    TOOL_CONTRACTS,
    SqliteInput,
    analysis_operations,
    contract_input_example,
)


def test_contract_names_are_unique() -> None:
    names = [contract.name for contract in TOOL_CONTRACTS]
    assert len(names) == len(set(names))


def test_analysis_operations_match_providers() -> None:
    operations = analysis_operations(build_providers())
    assert "inspect_binary_layout" in operations
    assert "inspect_go_binary" in operations
    assert "inspect_rust_binary" in operations
    assert "inspect_managed_artifact" in operations
    assert "inspect_sqlite_database" in operations
    assert "inspect_artifact" in operations
    assert "inspect_android_package" in operations
    assert "identify_flutter_build" in operations


def test_input_models_reject_extra_fields() -> None:
    with pytest.raises(ValidationError):
        SqliteInput(path="x", bogus=True)  # type: ignore[call-arg]


def test_row_limit_bounds() -> None:
    with pytest.raises(ValidationError):
        SqliteInput(row_limit=100000)
    assert SqliteInput(row_limit=5).row_limit == 5


def test_contract_examples_are_valid() -> None:
    # Contracts whose inputs have required fields cannot be built from defaults.
    requires_input = {
        "open_binary",
        "evidence_export",
        "evidence_import",
        "inspect_analysis_view",
        "search",
        "compare_evidence",
        "capture_process",
        "disassemble_managed_method",
        "record_unknown",
        "update_unknown",
        "snapshot_export",
        "snapshot_import",
        "compare_network_captures",
        "evaluate_reconstruction_coverage",
        "compare_web_captures",
        "compare_managed_members",
        "observe_web_page",
        "decompile_android_class",
        "android_app_info",
        "adb_shell",
        "inspect_recorded_crash",
        "extract_firmware",
        "decompile_jeb_item",
        "verify_reconstruction",
        "verify_unknown_resolution",
        "batch_decompile",
        "build_call_path",
        "trace_call_path",
        "trace_feature",
        "trace_native_values",
        "compare_bundles",
        "compare_functions",
        "compare_process_captures",
        "correlate_static_and_runtime",
        "find_changed_behavior",
        "search_android_classes",
        "inspect_android_class",
        "inspect_android_method",
        "trace_android_references",
        "capture_process_scenario",
        "compare_artifacts",
        "export_evidence_bundle",
        "import_evidence_bundle",
        "inspect_managed_native_boundaries",
        "verify_managed_native_boundaries",
        "import_managed_reconstruction",
        "project_managed_application_graph",
        "decompile_managed_csharp",
        "project_android_application_graph",
        "project_apple_application_graph",
        "project_harmony_application_graph",
        "compare_wasm_interfaces",
        "match_native_functions",
        "invoke_webmcp_tool",
        "compare_application_versions",
        "compare_source_to_bundle",
        "trace_application_feature",
        "trace_javascript_semantics",
        "compare_javascript_export_shapes",
    }
    for contract in TOOL_CONTRACTS:
        if contract.name in requires_input:
            continue
        example = contract_input_example(contract)
        contract.input_model(**example)


def test_lookup_by_name() -> None:
    assert CONTRACTS_BY_NAME["open_binary"].operation is None
    assert CONTRACTS_BY_NAME["inspect_go_binary"].operation == "inspect_go_binary"
