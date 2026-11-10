"""Optional Python check plugins.

A plugin is a Python file named by REA_PLUGIN_PATHS (os.pathsep-separated). It
may export ``CHECKS`` (objects with id/run) or ``register(registry)``. Plugins
are explicit user code; rea-python never discovers or downloads them.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import sys
import threading
from pathlib import Path
from typing import Any, Protocol

from .deadlines import timeout_seconds


class PluginCheck(Protocol):
    id: str

    def run(self, store: Any, round_number: int) -> Any: ...


def plugin_paths() -> list[Path]:
    raw = os.environ.get("REA_PLUGIN_PATHS", "")
    return [Path(item).expanduser() for item in raw.split(os.pathsep) if item.strip()]


def load_plugin_checks() -> list[PluginCheck]:
    checks: list[PluginCheck] = []
    for index, path in enumerate(plugin_paths()):
        if not path.is_file():
            continue
        try:
            spec = importlib.util.spec_from_file_location(f"rea_plugin_{index}", path)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except Exception:
            continue
        values = getattr(module, "CHECKS", None)
        if isinstance(values, (list, tuple)):
            checks.extend(item for item in values if hasattr(item, "run"))
        register = getattr(module, "register", None)
        if callable(register):

            class Registry:
                def add(self, check: PluginCheck) -> None:
                    checks.append(check)

            register(Registry())
    return checks


def _wasmtime() -> Any | None:
    try:
        return importlib.import_module("wasmtime")
    except Exception:
        candidate = Path(__file__).resolve().parents[3] / "vendor/python"
        if candidate.is_dir() and str(candidate) not in sys.path:
            sys.path.insert(0, str(candidate))
        try:
            return importlib.import_module("wasmtime")
        except Exception:
            return None


def run_wasm_checks(store: Any, round_number: int) -> list[Any]:
    from ..domain.check import CheckResult

    wasmtime = _wasmtime()
    if wasmtime is None:
        return []
    raw = os.environ.get("REA_WASM_PLUGINS", "")
    results = []
    for item in [part for part in raw.split(os.pathsep) if part.strip()]:
        path = Path(item).expanduser()
        if not path.is_file():
            continue
        try:
            config = wasmtime.Config()
            config.epoch_interruption = True
            engine = wasmtime.Engine(config)
            store = wasmtime.Store(engine)
            limit = timeout_seconds("wasm", 30.0)
            store.set_epoch_deadline(1)
            timer = threading.Timer(limit, engine.increment_epoch)
            timer.start()
            try:
                module = wasmtime.Module.from_file(engine, str(path))
                instance = wasmtime.Instance(store, module, [])
                check = instance.exports(store).get("check")
                if check is None:
                    results.append(
                        CheckResult(f"wasm:{path.stem}", round_number, False, "no check export")
                    )
                    timer.cancel()
                    continue
                passed = int(check(store)) == 1
            finally:
                timer.cancel()
            results.append(
                CheckResult(
                    f"wasm:{path.stem}",
                    round_number,
                    passed,
                    "check returned 1" if passed else "check returned 0",
                )
            )
        except Exception as cause:
            results.append(CheckResult(f"wasm:{path.stem}", round_number, False, str(cause)))
    return results


def run_plugin_checks(store: Any, round_number: int) -> list[Any]:
    results = []
    for check in load_plugin_checks():
        try:
            result = check.run(store, round_number)
        except Exception as cause:
            from ..domain.check import CheckResult

            result = CheckResult(
                str(getattr(check, "id", "plugin")), round_number, False, str(cause)
            )
        results.append(result)
    return results


__all__ = ["PluginCheck", "load_plugin_checks", "plugin_paths", "run_plugin_checks"]
