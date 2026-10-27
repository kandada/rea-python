from __future__ import annotations

import os

import pytest

from benchmarks.measure_schema import measure
from benchmarks.run_task_benchmark import run_task


async def test_schema_benchmark_core_is_smaller_than_full() -> None:
    core = await measure("core")
    full = await measure("full")
    assert core["tools"] < full["tools"]
    assert core["schema_bytes"] < full["schema_bytes"] // 5
    assert core["schema_tokens"] < full["schema_tokens"] // 5


def test_task_benchmark_measures_a_real_cli_sequence() -> None:
    result = run_task(
        {
            "id": "providers",
            "commands": [["providers"]],
            "required": ["providers"],
        },
        None,
    )
    assert result["success"] is True
    assert result["turns"] == 1
    assert result["tokens"] > 0
    assert result["outputs"][0]["exit_code"] == 0


@pytest.mark.skipif(os.name == "nt", reason="uses /bin/ls as a portable fixture")
def test_task_benchmark_inserts_target_after_command() -> None:
    result = run_task(
        {
            "id": "triage",
            "commands": [["triage"]],
            "required": ["format"],
        },
        "/bin/ls",
    )
    assert result["success"] is True
    assert result["outputs"][0]["exit_code"] == 0
    assert '"format"' in result["outputs"][0]["stdout"]


def test_benchmark_empty_targets_are_skipped() -> None:
    from benchmarks.run_task_benchmark import run_tasks

    report = run_tasks(
        [{"id": "missing", "target_key": "missing", "commands": [["providers"]]}],
        {},
    )
    assert report["skipped"] if "skipped" in report else report["tasks"][0]["skipped"] is True
    assert report["executed"] == 0
