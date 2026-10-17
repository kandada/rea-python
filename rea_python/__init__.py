"""Compatibility alias package for :mod:`rea_mcp`.

``import rea_python`` exposes the same API as ``import rea_mcp``: every submodule
of ``rea_mcp`` is registered under ``rea_python.*`` in ``sys.modules`` and the
first-level packages are attached as attributes. ``rea_python`` stays a real
package so ``python -m rea_python`` also works.
"""

from __future__ import annotations

import importlib
import pkgutil
import sys

import rea_mcp as _impl

__version__ = _impl.__version__
__all__ = list(getattr(_impl, "__all__", []))

for _info in pkgutil.walk_packages(_impl.__path__, prefix="rea_mcp."):
    if _info.name.endswith(".__main__"):
        continue
    try:
        _module = importlib.import_module(_info.name)
    except Exception:  # pragma: no cover - optional-dependency surface
        continue
    _suffix = _info.name[len("rea_mcp.") :]
    sys.modules.setdefault("rea_python." + _suffix, _module)
    if "." not in _suffix:
        sys.modules[__name__].__dict__[_suffix] = _module
