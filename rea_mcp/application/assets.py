"""Caller-supplied asset generation adapter."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.result import Result, err, ok
from ..process.argv import split_command


def generate_asset(prompt: str, output: str) -> Result[dict[str, object], AnalysisError]:
    command = os.environ.get("REA_ASSET_COMMAND")
    if not command:
        return err(
            AnalysisInputError(
                operation="asset-generate",
                message="set REA_ASSET_COMMAND to an image/3D asset generator",
            )
        )
    destination = Path(output).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    parts = [
        part.replace("{prompt}", prompt).replace("{output}", str(destination))
        for part in split_command(command)
    ]
    if not any("{prompt}" in part or "{output}" in part for part in split_command(command)):
        parts = [*split_command(command), prompt, str(destination)]
    try:
        process = subprocess.run(
            parts,
            capture_output=True,
            text=True,
            timeout=300,
            env=os.environ.copy(),
        )
    except (OSError, subprocess.TimeoutExpired) as cause:
        return err(AnalysisInputError(operation="asset-generate", message=str(cause)))
    if process.returncode != 0:
        return err(
            AnalysisInputError(
                operation="asset-generate",
                message=f"asset command failed: {(process.stderr or process.stdout)[-2000:]}",
            )
        )
    if not destination.is_file():
        return err(
            AnalysisInputError(
                operation="asset-generate", message="asset command did not write the output file"
            )
        )
    return ok({"output": str(destination), "bytes": destination.stat().st_size})


__all__ = ["generate_asset"]
