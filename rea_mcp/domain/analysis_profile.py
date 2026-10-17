"""Analysis profile commitment.

An analysis profile binds a provider identity and the parameters that affect its
results, with a canonical digest. It is the cache key's semantic component and the
basis for cross-session comparability.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .canonical import digest_canonical
from .json_value import normalize_json_value


class ProviderIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    version: str | None = None


class AnalysisProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: ProviderIdentity
    parameters: dict[str, Any]
    digest: str


def create_analysis_profile(
    provider: ProviderIdentity,
    parameters: dict[str, Any] | None = None,
) -> AnalysisProfile:
    """Create a validated profile commitment with a canonical digest."""

    normalized = normalize_json_value(parameters or {})
    unsigned = {"provider": provider.model_dump(), "parameters": normalized}
    return AnalysisProfile(
        provider=provider,
        parameters=normalized,
        digest=digest_canonical(unsigned),
    )


def analysis_profiles_equal(left: AnalysisProfile, right: AnalysisProfile) -> bool:
    return left.digest == right.digest and left.provider == right.provider


__all__ = [
    "AnalysisProfile",
    "ProviderIdentity",
    "analysis_profiles_equal",
    "create_analysis_profile",
]
