"""Relationship and facet coverage declarations.

A provider reports whether the relationships it observed (callers, callees,
references) are complete, partial, or unknown. Consumers must not treat an empty
collection with partial/unknown coverage as proof that nothing exists.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class RelationshipCoverage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["complete", "partial", "unknown"]
    reason: str | None = None

    @classmethod
    def complete(cls) -> RelationshipCoverage:
        return cls(status="complete")

    @classmethod
    def unknown(cls, reason: str) -> RelationshipCoverage:
        return cls(status="unknown", reason=reason)


class FacetAvailability(BaseModel):
    """Whether a provider facet (pseudocode, assembly, ...) was observed."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    available: bool
    reason: str | None = None


__all__ = ["FacetAvailability", "Field", "RelationshipCoverage"]
