"""Process entry points for the ``rea-mcp`` command and ``python -m rea_mcp``."""

from __future__ import annotations

import sys


def cli_main() -> None:
    """Console-script entry point (``rea-mcp`` / ``rea-python`` / ``rea``)."""

    from ..cli.app import app

    # Output is always JSON. Accept a bare ``--json`` flag anywhere before a
    # ``--`` separator so documented examples work; ``--`` passes the rest
    # through unchanged (e.g. ``capture-process -- prog --json``).
    cleaned: list[str] = []
    passthrough = False
    for arg in sys.argv[1:]:
        if arg == "--":
            passthrough = True
        if arg == "--json" and not passthrough:
            continue
        cleaned.append(arg)
    sys.argv = [sys.argv[0], *cleaned]

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
