"""Session-owned investigation records: the Evidence ledger and unknown registry."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..domain.analysis_error import AnalysisError, EvidenceIntegrityError, UnknownRegistryError
from ..domain.evidence import Evidence, parse_evidence
from ..domain.evidence_bundle import create_evidence_bundle, parse_evidence_bundle
from ..domain.residual_unknown import (
    RecordUnknownInput,
    ResidualUnknown,
    UnknownStatus,
    create_residual_unknown,
    update_residual_unknown,
)
from ..domain.result import Result, err, ok


@dataclass
class ImportDelta:
    records_added: int
    unknowns_added: int
    changed: bool


class EvidenceLedger:
    """An idempotent, immutable set of Evidence records plus unknown revisions."""

    def __init__(self) -> None:
        self._records: dict[str, Evidence] = {}
        self._unknown_revisions: dict[str, ResidualUnknown] = {}
        self._unknown_heads: dict[str, ResidualUnknown] = {}

    def record(self, evidence: Evidence) -> Result[str, EvidenceIntegrityError]:
        parsed = parse_evidence(evidence.model_dump())
        if not parsed.ok:
            return err(parsed.error)
        authenticated = parsed.value
        existing = self._records.get(authenticated.evidence_id)
        if existing is not None:
            if _records_agree(existing, authenticated):
                return ok("duplicate")
            return err(EvidenceIntegrityError(message="Conflicting evidence record"))
        self._records[authenticated.evidence_id] = authenticated
        return ok("added")

    def has(self, evidence_id: str) -> bool:
        return evidence_id in self._records

    def get(self, evidence_id: str) -> Evidence | None:
        record = self._records.get(evidence_id)
        return None if record is None else record.model_copy(deep=True)

    def records(self) -> list[Evidence]:
        return [record.model_copy(deep=True) for record in self._records.values()]

    def clear(self) -> None:
        self._records.clear()
        self._unknown_revisions.clear()
        self._unknown_heads.clear()

    @property
    def record_count(self) -> int:
        return len(self._records)

    def export_bundle(self) -> Any:
        return create_evidence_bundle(
            list(self._records.values()),
            [unknown.model_dump() for unknown in self._unknown_revisions.values()],
        )

    def import_bundle(self, payload: Any) -> Result[ImportDelta, AnalysisError]:
        parsed = parse_evidence_bundle(payload)
        if not parsed.ok:
            return err(parsed.error)
        bundle = parsed.value
        additions: dict[str, Evidence] = {}
        for record in bundle.records:
            existing = self._records.get(record.evidence_id) or additions.get(record.evidence_id)
            if existing is not None:
                if not _records_agree(existing, record):
                    return err(EvidenceIntegrityError(message="Conflicting evidence record"))
                continue
            additions[record.evidence_id] = record
        # Commit only after full validation (atomic merge).
        for evidence_id, record in additions.items():
            self._records[evidence_id] = record
        unknowns_added = 0
        for unknown_payload in bundle.unknowns:
            try:
                unknown = ResidualUnknown.model_validate(unknown_payload)
            except Exception as cause:
                return err(
                    EvidenceIntegrityError(
                        message="Bundle unknown revision is invalid", details={"cause": str(cause)}
                    )
                )
            key = f"{unknown.unknown_id}:{unknown.revision}"
            if key not in self._unknown_revisions:
                unknowns_added += 1
            self._unknown_revisions[key] = unknown
            head = self._unknown_heads.get(unknown.unknown_id)
            if head is None or head.revision < unknown.revision:
                self._unknown_heads[unknown.unknown_id] = unknown
        return ok(
            ImportDelta(
                records_added=len(additions),
                unknowns_added=unknowns_added,
                changed=bool(additions) or unknowns_added > 0,
            )
        )


class InvestigationRecords:
    """Facade over the ledger with an unknown registry."""

    def __init__(self) -> None:
        self._ledger = EvidenceLedger()

    @property
    def ledger(self) -> EvidenceLedger:
        return self._ledger

    def record_evidence(self, evidence: Evidence) -> Result[str, EvidenceIntegrityError]:
        return self._ledger.record(evidence)

    def record_unknown(
        self, input: RecordUnknownInput, mutation_evidence_ids: list[str]
    ) -> Result[ResidualUnknown, AnalysisError]:
        try:
            unknown = create_residual_unknown(input, mutation_evidence_ids)
        except Exception as cause:
            return err(UnknownRegistryError(reason="invalid-transition", message=str(cause)))
        if unknown.unknown_id in self._ledger._unknown_heads:
            return err(UnknownRegistryError(reason="already-exists"))
        key = f"{unknown.unknown_id}:{unknown.revision}"
        self._ledger._unknown_revisions[key] = unknown
        self._ledger._unknown_heads[unknown.unknown_id] = unknown
        return ok(unknown)

    def update_unknown(
        self,
        unknown_id: str,
        *,
        status: UnknownStatus,
        mutation_evidence_id: str,
        **kwargs: Any,
    ) -> Result[ResidualUnknown, AnalysisError]:
        current = self._ledger._unknown_heads.get(unknown_id)
        if current is None:
            return err(UnknownRegistryError(reason="not-found"))
        updated = update_residual_unknown(
            current, status=status, mutation_evidence_id=mutation_evidence_id, **kwargs
        )
        if not updated.ok:
            return err(updated.error)
        value = updated.value
        self._ledger._unknown_revisions[f"{value.unknown_id}:{value.revision}"] = value
        self._ledger._unknown_heads[value.unknown_id] = value
        return ok(value)

    def list_unknowns(self) -> list[ResidualUnknown]:
        return [
            unknown.model_copy(deep=True)
            for unknown in sorted(
                self._ledger._unknown_heads.values(), key=lambda item: item.unknown_id
            )
        ]


def _records_agree(left: Evidence, right: Evidence) -> bool:
    left_projection = _identity_projection(left)
    right_projection = _identity_projection(right)
    return left_projection == right_projection


def _identity_projection(evidence: Evidence) -> dict[str, Any]:
    from ..domain.evidence import evidence_without_display_fields

    projection = evidence_without_display_fields(evidence)
    return {**projection, "evidence_id": evidence.evidence_id}


__all__ = ["EvidenceLedger", "ImportDelta", "InvestigationRecords"]
