"""Source locations attached to an Evidence observation."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AddressLocation(_Base):
    kind: Literal["address"] = "address"
    address: str = Field(min_length=1)


class AddressRangeLocation(_Base):
    kind: Literal["address-range"] = "address-range"
    start: str = Field(min_length=1)
    end: str = Field(min_length=1)


class ArtifactPathLocation(_Base):
    kind: Literal["artifact-path"] = "artifact-path"
    path: str = Field(min_length=1)


class FileOffsetLocation(_Base):
    kind: Literal["file-offset"] = "file-offset"
    offset: int = Field(ge=0)


class FileOffsetRangeLocation(_Base):
    kind: Literal["file-offset-range"] = "file-offset-range"
    start: int = Field(ge=0)
    end: int = Field(ge=0)


EvidenceLocation = (
    AddressLocation
    | AddressRangeLocation
    | ArtifactPathLocation
    | FileOffsetLocation
    | FileOffsetRangeLocation
)


__all__ = [
    "AddressLocation",
    "AddressRangeLocation",
    "ArtifactPathLocation",
    "EvidenceLocation",
    "FileOffsetLocation",
    "FileOffsetRangeLocation",
]
