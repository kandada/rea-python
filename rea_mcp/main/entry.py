"""Process entry points for the ``rea-mcp`` command and ``python -m rea_mcp``."""

from __future__ import annotations

import sys

_GLOBAL_FLAGS = {"--token-count", "--version"}
_GLOBAL_VALUES = {"--output-budget", "--filter-output", "--output-dir"}


def normalize_global_options(argv: list[str]) -> list[str]:
    """Move known global options before the subcommand.

    Click/Typer only accepts group options before the command. Keeping this in
    one place avoids duplicating ``--output-budget`` on hundreds of commands.
    """

    global_parts: list[str] = []
    rest: list[str] = []
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--":
            rest.extend(argv[index:])
            break
        if arg == "--json":
            index += 1
            continue
        if arg in _GLOBAL_VALUES and index + 1 < len(argv):
            global_parts.extend([arg, argv[index + 1]])
            index += 2
            continue
        matched = next(
            (name for name in _GLOBAL_VALUES if arg.startswith(f"{name}=")),
            None,
        )
        if matched is not None:
            global_parts.append(arg)
            index += 1
            continue
        if arg in _GLOBAL_FLAGS:
            global_parts.append(arg)
            index += 1
            continue
        rest.append(arg)
        index += 1
    return [*global_parts, *rest]


def cli_main() -> None:
    """Console-script entry point (``rea-mcp`` / ``rea-python`` / ``rea``)."""

    from ..cli.app import app

    sys.argv = [sys.argv[0], *normalize_global_options(sys.argv[1:])]

    try:
        app()
    except BrokenPipeError:
        try:
            import os

            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except OSError:
            pass
        raise SystemExit(141) from None


def main() -> None:
    cli_main()


if __name__ == "__main__":  # pragma: no cover
    main()


__all__ = ["cli_main", "main"]
