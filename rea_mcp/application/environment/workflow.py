"""End-to-end environment preparation from manifest and capture Evidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ...domain.analysis_error import AnalysisInputError
from ...domain.result import Result, err, ok
from .bundle import EnvironmentBundlePlan, plan_environment_bundle
from .coverage import environment_coverage
from .extract import ExtractionResult, extract_state
from .replay import replay_tool
from .source import EnvironmentSource, load_environment_source
from .state_store import EnvironmentStateStore


@dataclass
class PreparedEnvironment:
    source: EnvironmentSource
    extraction: ExtractionResult
    store: EnvironmentStateStore
    coverage: dict[str, Any]
    bundle: EnvironmentBundlePlan


def prepare_environment(
    manifest_value: Any,
    evidence_value: Any,
    *,
    name: str | None = None,
    package_source: dict[str, Any] | None = None,
) -> Result[PreparedEnvironment, AnalysisInputError]:
    loaded = load_environment_source(manifest_value, evidence_value)
    if not loaded.ok:
        return err(loaded.error)
    source = loaded.value
    extraction = extract_state(source)
    store = EnvironmentStateStore.from_state(extraction.state)
    coverage = environment_coverage(store)
    check = None
    for tool in source.manifest.get("tools") or []:
        if tool.get("method") != "GET" or tool.get("parameters"):
            continue
        answer = replay_tool(source, str(tool.get("name") or ""), {})
        if answer.ok:
            check = {
                "tool": answer.tool,
                "status": answer.status,
                "recordOrdinal": answer.record_ordinal,
            }
            break
    plan = plan_environment_bundle(
        {"name": name or source.manifest.get("name") or "environment"},
        name=name,
        package_source=package_source,
        tool_count=len(source.manifest.get("tools") or []),
        state={"served": True, "evidence_id": source.evidence_id},
        check=check,
    )
    if not plan.ok:
        return err(plan.error)
    return ok(
        PreparedEnvironment(
            source=source,
            extraction=extraction,
            store=store,
            coverage=coverage,
            bundle=plan.value,
        )
    )


__all__ = ["PreparedEnvironment", "prepare_environment"]
