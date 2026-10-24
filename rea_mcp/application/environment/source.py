"""Authenticated environment manifest/capture loading and replay body projection."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from ...domain.analysis_error import AnalysisInputError
from ...domain.result import Result, err, ok

ENVIRONMENT_SERVE_OPERATION = "environment-serve"
REPLAY_BODY_LIMIT_BYTES = 256 * 1024


@dataclass
class RecordedExchange:
    ordinal: int
    path: str
    query: str | None
    status: int | None
    content_type: str | None
    body_text: str | None
    body_encoding: str | None = None
    body_cut: bool = False


@dataclass
class EnvironmentSource:
    manifest: dict[str, Any]
    manifest_evidence_id: str
    evidence_id: str
    capture_kind: str
    capture_sha256: str | None
    exchanges: dict[int, RecordedExchange] = field(default_factory=dict)


def _error(message: str, role: str) -> AnalysisInputError:
    return AnalysisInputError(
        message=message,
        operation=ENVIRONMENT_SERVE_OPERATION,
        details={"issues": [{"path": [role], "reason": "invalid_value", "message": message}]},
    )


def _evidence_view(value: Any, role: str, kind: str) -> tuple[dict[str, Any], str] | None:
    if not isinstance(value, dict) or not isinstance(value.get("normalized_result"), dict):
        return None
    normalized = value["normalized_result"]
    if normalized.get("kind") != kind:
        return None
    evidence_id = value.get("evidence_id")
    if not isinstance(evidence_id, str):
        return None
    return normalized, evidence_id


def _har_exchanges(normalized: dict[str, Any]) -> list[RecordedExchange]:
    entries = normalized.get("entries")
    if not isinstance(entries, list):
        return []
    exchanges: list[RecordedExchange] = []
    for ordinal, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        request = entry.get("request") or {}
        response = entry.get("response") or {}
        url = str(request.get("url") or "")
        parsed = urlsplit(url)
        content = response.get("content") or {}
        body_text = content.get("text")
        encoding = content.get("encoding")
        if isinstance(encoding, str) and encoding.lower() == "base64":
            body_encoding = "base64"
        else:
            body_encoding = None
        exchanges.append(
            RecordedExchange(
                ordinal=ordinal,
                path=parsed.path or "/",
                query=("?" + parsed.query) if parsed.query else None,
                status=response.get("status") if isinstance(response.get("status"), int) else None,
                content_type=content.get("mimeType") or None,
                body_text=body_text if isinstance(body_text, str) else None,
                body_encoding=body_encoding,
                body_cut=bool(content.get("_truncated")),
            )
        )
    return exchanges


def load_environment_source(
    manifest_value: Any, evidence_value: Any
) -> Result[EnvironmentSource, AnalysisInputError]:
    manifest = _evidence_view(manifest_value, "manifest", "environment-manifest")
    if manifest is None:
        return err(
            _error("The manifest file is not an environment-manifest Evidence record.", "manifest")
        )
    view, manifest_id = manifest
    capture = _evidence_view(evidence_value, "evidence", "environment-capture")
    view_capture: dict[str, Any]
    if capture is None:
        # Accept the older network-capture projection shape as a fallback.
        raw = evidence_value.get("normalized_result") if isinstance(evidence_value, dict) else None
        if isinstance(raw, dict) and raw.get("capture_format") == "har":
            view_capture = {
                "kind": "environment-capture",
                "entries": [],
                "artifact": raw.get("artifact") or {},
            }
            evidence_id = str(evidence_value.get("evidence_id") or "")
        else:
            return err(_error("The evidence file is not an environment capture.", "evidence"))
    else:
        view_capture, evidence_id = capture
    parent = view.get("parent_evidence_id")
    if parent != evidence_id:
        return err(
            _error(
                f"The manifest cites parent Evidence {parent}; the evidence file is {evidence_id}.",
                "evidence",
            )
        )
    exchanges = _har_exchanges(view_capture)
    if not exchanges:
        for ordinal, request in enumerate(view_capture.get("requests") or []):
            if not isinstance(request, dict):
                continue
            parsed = urlsplit(str(request.get("url") or ""))
            exchanges.append(
                RecordedExchange(
                    ordinal=ordinal,
                    path=parsed.path or "/",
                    query=("?" + parsed.query) if parsed.query else None,
                    status=request.get("status")
                    if isinstance(request.get("status"), int)
                    else None,
                    content_type=request.get("mime_type"),
                    body_text=None,
                )
            )
    artifact = view_capture.get("artifact")
    return ok(
        EnvironmentSource(
            manifest=view,
            manifest_evidence_id=manifest_id,
            evidence_id=evidence_id,
            capture_kind=str(view_capture.get("kind") or "web-network-capture"),
            capture_sha256=artifact.get("sha256") if isinstance(artifact, dict) else None,
            exchanges={exchange.ordinal: exchange for exchange in exchanges},
        )
    )


def load_probe_exchanges(value: Any) -> list[RecordedExchange]:
    view = _evidence_view(value, "evidence", "environment-capture")
    if view is not None:
        return _har_exchanges(view[0])
    if isinstance(value, dict):
        raw = value.get("normalized_result")
        if isinstance(raw, dict):
            return _har_exchanges(raw)
    return []


def replayed_body(exchange: RecordedExchange) -> dict[str, Any]:
    text = exchange.body_text
    if text is None:
        return {"kind": "none"}
    if exchange.body_encoding == "base64":
        try:
            decoded = base64.b64decode(text, validate=True)
        except ValueError:
            decoded = b""
        return {
            "kind": "base64",
            "encoded": text,
            "whole": not exchange.body_cut and len(decoded) <= REPLAY_BODY_LIMIT_BYTES,
        }
    encoded = text.encode("utf-8")
    if exchange.body_cut or len(encoded) > REPLAY_BODY_LIMIT_BYTES:
        return {"kind": "cut", "text": text}
    content_type = (exchange.content_type or "").lower()
    if "json" in content_type:
        try:
            return {"kind": "json", "value": json.loads(text)}
        except json.JSONDecodeError:
            pass
    return {"kind": "text", "text": text}


__all__ = [
    "ENVIRONMENT_SERVE_OPERATION",
    "REPLAY_BODY_LIMIT_BYTES",
    "EnvironmentSource",
    "RecordedExchange",
    "load_environment_source",
    "load_probe_exchanges",
    "replayed_body",
]
