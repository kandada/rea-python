"""Lazy compatibility-package aliases for :mod:`rea` and :mod:`rea_python`."""

from __future__ import annotations

import importlib
import importlib.abc
import importlib.util
import sys
from collections.abc import Sequence
from types import ModuleType
from typing import Any


class _AliasLoader(importlib.abc.Loader):
    def __init__(self, target_name: str) -> None:
        self.target_name = target_name
        self._restore: dict[str, Any] = {}

    def create_module(self, spec: importlib.machinery.ModuleSpec) -> ModuleType:
        module = importlib.import_module(self.target_name)
        self._restore = {
            key: getattr(module, key)
            for key in (
                "__name__",
                "__package__",
                "__spec__",
                "__loader__",
                "__file__",
                "__cached__",
            )
            if hasattr(module, key)
        }
        if hasattr(module, "__path__"):
            self._restore["__path__"] = module.__path__
        return module

    def exec_module(self, module: ModuleType) -> None:
        for key, value in self._restore.items():
            setattr(module, key, value)


class _AliasFinder(importlib.abc.MetaPathFinder):
    def __init__(self, alias: str, target: str) -> None:
        self.alias = alias
        self.target = target
        self.prefix = alias + "."

    def find_spec(
        self, fullname: str, path: Sequence[str] | None = None, target: ModuleType | None = None
    ) -> importlib.machinery.ModuleSpec | None:
        if not fullname.startswith(self.prefix):
            return None
        if fullname.endswith(".__main__"):
            return None
        target_name = self.target + fullname[len(self.alias) :]
        try:
            target_module = importlib.import_module(target_name)
        except ModuleNotFoundError:
            return None
        spec = importlib.util.spec_from_loader(
            fullname,
            _AliasLoader(target_name),
            is_package=hasattr(target_module, "__path__"),
        )
        if spec is not None:
            spec.origin = getattr(target_module, "__file__", None)
        return spec


def install_alias(alias: str, target: str) -> None:
    """Map ``alias.*`` imports onto ``target.*`` without eagerly importing them."""

    if any(isinstance(finder, _AliasFinder) and finder.alias == alias for finder in sys.meta_path):
        return
    sys.meta_path.insert(0, _AliasFinder(alias, target))


def alias_getattr(alias: str, target: str, name: str) -> ModuleType:
    module = importlib.import_module(f"{target}.{name}")
    sys.modules[f"{alias}.{name}"] = module
    return module


__all__ = ["alias_getattr", "install_alias"]
