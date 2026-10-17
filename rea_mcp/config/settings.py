"""Runtime configuration parsed from the environment (``REA_*`` variables)."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

_LOG_LEVELS = {"trace", "debug", "info", "warn", "error", "silent"}
_DEFAULT_RESPONSE_BUDGET = 10 * 1024 * 1024


class AppConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="REA_", extra="ignore")

    analysis_provider: str = Field(default="auto", description="Default provider selector.")
    log_level: str = "info"
    mcp_max_response_bytes: int = Field(default=_DEFAULT_RESPONSE_BUDGET, ge=1024)
    mcp_input_schema_profile: str = Field(
        default="full",
        description="'full' or 'compact'; compact fits schema-size-constrained clients.",
    )

    @property
    def effective_input_schema_profile(self) -> str:
        return "compact" if self.mcp_input_schema_profile.lower() == "compact" else "full"

    @property
    def effective_log_level(self) -> str:
        level = self.log_level.lower()
        return level if level in _LOG_LEVELS else "info"


__all__ = ["AppConfig"]
