"""The ``rea`` and ``rea_python`` aliases must match the ``rea_mcp`` implementation."""

from __future__ import annotations

import pytest


@pytest.mark.parametrize("alias", ["rea", "rea_python"])
def test_alias_exposes_version(alias: str) -> None:
    import importlib

    import rea_mcp

    module = importlib.import_module(alias)
    assert module.__version__ == rea_mcp.__version__
    assert module.main is rea_mcp.main
    assert module.domain is rea_mcp.domain


@pytest.mark.parametrize("alias", ["rea", "rea_python"])
def test_nested_submodules_are_shared(alias: str) -> None:
    import importlib

    from rea_mcp.domain.result import ok as impl_ok

    module = importlib.import_module(f"{alias}.domain.result")
    assert module.ok is impl_ok

    registry = importlib.import_module(f"{alias}.providers.registry")
    import rea_mcp.providers.registry as impl_registry

    assert registry is impl_registry


@pytest.mark.parametrize("alias", ["rea", "rea_python"])
def test_cli_entry_is_shared(alias: str) -> None:
    import importlib

    from rea_mcp.main.entry import cli_main as impl_cli

    entry = importlib.import_module(f"{alias}.main.entry")
    assert entry.cli_main is impl_cli
