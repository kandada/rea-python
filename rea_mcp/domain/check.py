"""Structured checks for one craft round."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


def _now() -> int:
    return int(time.time() * 1000)


@dataclass
class Claim:
    title: str
    passed: bool
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"title": self.title, "passed": self.passed, "detail": self.detail}

    @classmethod
    def from_dict(cls, value: Any) -> Claim:
        if not isinstance(value, dict):
            return cls("claim", False, "invalid claim")
        return cls(
            str(value.get("title") or "claim"),
            bool(value.get("passed")),
            str(value.get("detail") or ""),
        )


@dataclass
class CheckResult:
    check: str
    round: int
    passed: bool
    note: str = ""
    similarity: float | None = None
    good_enough: float | None = None
    claims: list[Claim] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    at: int = field(default_factory=_now)

    def good(self, default_threshold: float) -> bool:
        return (
            self.passed
            and not self.unknowns
            and all(claim.passed for claim in self.claims)
            and (
                self.similarity is None
                or self.similarity >= (self.good_enough or default_threshold)
            )
        )

    def failed_claims(self) -> list[Claim]:
        return [claim for claim in self.claims if not claim.passed]

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "round": self.round,
            "passed": self.passed,
            "note": self.note,
            "similarity": self.similarity,
            "good_enough": self.good_enough,
            "claims": [claim.to_dict() for claim in self.claims],
            "unknowns": self.unknowns,
            "artifacts": self.artifacts,
            "at": self.at,
        }

    @classmethod
    def from_dict(cls, value: Any) -> CheckResult:
        if not isinstance(value, dict):
            return cls("unknown", 0, False, "invalid check")
        return cls(
            check=str(value.get("check") or "unknown"),
            round=int(value.get("round") or 0),
            passed=bool(value.get("passed")),
            note=str(value.get("note") or ""),
            similarity=float(value["similarity"])
            if isinstance(value.get("similarity"), (int, float))
            else None,
            good_enough=float(value["good_enough"])
            if isinstance(value.get("good_enough"), (int, float))
            else None,
            claims=[Claim.from_dict(item) for item in value.get("claims") or []],
            unknowns=[str(item) for item in value.get("unknowns") or []],
            artifacts=[str(item) for item in value.get("artifacts") or []],
            at=int(value.get("at") or _now()),
        )


__all__ = ["CheckResult", "Claim"]
