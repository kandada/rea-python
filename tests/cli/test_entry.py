from __future__ import annotations

import sys

from rea_mcp.main import entry


def test_cli_main_normalizes_arguments(monkeypatch) -> None:
    called: list[list[str]] = []
    import rea_mcp.cli.app as cli_app

    monkeypatch.setattr(cli_app, "app", lambda: called.append(list(sys.argv)))
    monkeypatch.setattr(
        sys,
        "argv",
        ["rea", "providers", "--output-budget", "10", "--json", "--token-count"],
    )
    entry.cli_main()
    assert called == [["rea", "--output-budget", "10", "--token-count", "providers"]]


def test_normalize_keeps_passthrough() -> None:
    assert entry.normalize_global_options(
        ["capture-process", "--", "prog", "--output-budget", "5"]
    ) == ["capture-process", "--", "prog", "--output-budget", "5"]
