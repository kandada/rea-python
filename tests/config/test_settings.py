from rea_mcp.config.settings import AppConfig, client_schema_matrix


def test_client_schema_matrix_shape() -> None:
    rows = client_schema_matrix()
    clients = {row["client"] for row in rows}
    assert {"generic", "cursor", "vscode", "opencode", "zed"} <= clients
    for row in rows:
        assert row["input_schema"] in {"full", "compact"}
        assert row["output_schema"] in {"full", "off"}


def test_default_profile_is_full() -> None:
    config = AppConfig()
    assert config.effective_input_schema_profile == "full"
    assert config.effective_output_schema_profile == "full"


def test_client_preset_applied(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("REA_MCP_CLIENT", "vscode")
    config = AppConfig()
    assert config.effective_input_schema_profile == "compact"
    assert config.effective_output_schema_profile == "off"


def test_explicit_profile_overrides_client(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("REA_MCP_CLIENT", "vscode")
    monkeypatch.setenv("REA_MCP_INPUT_SCHEMA_PROFILE", "full")
    config = AppConfig()
    assert config.effective_input_schema_profile == "full"
    assert config.effective_output_schema_profile == "off"


def test_compact_budget_is_configurable(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("REA_MCP_COMPACT_BUDGET_BYTES", "2048")
    config = AppConfig()
    assert config.mcp_compact_budget_bytes == 2048
