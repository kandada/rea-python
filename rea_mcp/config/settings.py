"""Runtime configuration parsed from the environment (``REA_*`` variables)."""

from __future__ import annotations

from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

_LOG_LEVELS = {"trace", "debug", "info", "warn", "error", "silent"}
_DEFAULT_RESPONSE_BUDGET = 512 * 1024
_DEFAULT_COMPACT_BUDGET = 13312

# Per-client schema presets. ``input`` is 'full' or 'compact'; ``output`` is 'full'
# or 'off'. Explicit REA_MCP_*_SCHEMA_PROFILE settings override the preset.
CLIENT_PRESETS: dict[str, dict[str, str]] = {
    "generic": {"input": "full", "output": "full"},
    "claude": {"input": "full", "output": "full"},
    "cursor": {"input": "compact", "output": "off"},
    "opencode": {"input": "compact", "output": "off"},
    "vscode": {"input": "compact", "output": "off"},
    "code": {"input": "compact", "output": "off"},
    "zed": {"input": "compact", "output": "off"},
    "minimal": {"input": "compact", "output": "off"},
}


class AppConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="REA_", extra="ignore")

    analysis_provider: str = Field(default="auto", description="Default provider selector.")
    log_level: str = "info"
    mcp_max_response_bytes: int = Field(default=_DEFAULT_RESPONSE_BUDGET, ge=1024)
    mcp_compact_budget_bytes: int = Field(
        default=_DEFAULT_COMPACT_BUDGET,
        ge=1024,
        description="Byte budget for a single compacted input schema.",
    )
    mcp_client: str = Field(
        default="generic",
        description="Client preset key for the schema matrix (see CLIENT_PRESETS).",
    )
    mcp_input_schema_profile: str = Field(
        default="auto",
        description="'full', 'compact', or 'auto' (follow the client preset).",
    )
    mcp_output_schema_profile: str = Field(
        default="auto",
        description="'full', 'off', or 'auto' (follow the client preset).",
    )
    mcp_toolset: str = Field(
        default="auto",
        description="Tool exposure preset: auto, core, full, or comma-separated domains.",
    )
    mcp_available_only: bool = Field(
        default=False,
        description="Hide tools whose declared provider operation is unavailable.",
    )

    @property
    def _preset(self) -> dict[str, str]:
        return CLIENT_PRESETS.get(self.mcp_client.lower(), CLIENT_PRESETS["generic"])

    @property
    def effective_input_schema_profile(self) -> str:
        explicit = self.mcp_input_schema_profile.lower()
        if explicit in ("full", "compact"):
            return explicit
        return self._preset["input"]

    @property
    def effective_output_schema_profile(self) -> str:
        explicit = self.mcp_output_schema_profile.lower()
        if explicit in ("full", "off"):
            return explicit
        return self._preset["output"]

    @property
    def effective_log_level(self) -> str:
        level = self.log_level.lower()
        return level if level in _LOG_LEVELS else "info"


def client_schema_matrix() -> list[dict[str, Any]]:
    """Return the per-client schema posture as a list of rows."""

    return [
        {
            "client": client,
            "input_schema": preset["input"],
            "output_schema": preset["output"],
        }
        for client, preset in CLIENT_PRESETS.items()
    ]


__all__ = ["CLIENT_PRESETS", "AppConfig", "client_schema_matrix"]
