"""Compatibility alias for :mod:`rea_mcp`.

Submodules load lazily through a meta-path finder, so ``import rea`` no longer
imports every optional provider before the caller asks for one.
"""

from __future__ import annotations

from types import ModuleType

import rea_mcp as _impl
from rea_mcp._alias import alias_getattr, install_alias

__version__ = _impl.__version__
__all__ = list(getattr(_impl, "__all__", []))

install_alias("rea", "rea_mcp")


def __getattr__(name: str) -> ModuleType:
    return alias_getattr("rea", "rea_mcp", name)
