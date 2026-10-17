"""Built-in SQLite database provider.

Reads tables, columns, indexes, views and triggers from a local database snapshot
using the standard-library ``sqlite3`` module in read-only mode.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any
from urllib.parse import quote

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import AnalysisProfile, ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="sqlite", name="REA-Python SQLite snapshots", version="1")


class SqliteDatabaseProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="inspect_sqlite_database",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                cache_policy="live",
                limitations=("Opens the database read-only; consistent with SQLite locking.",),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format == "sqlite":
            return TargetSupport("supported")
        return TargetSupport(
            "unsupported", reason="not a SQLite database", code="target_format_unsupported"
        )

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: AnalysisProfile | None,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del profile
        if operation != "inspect_sqlite_database":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        path = Path(target.path)
        uri = f"file:{quote(str(path))}?mode=ro"
        try:
            connection = sqlite3.connect(uri, uri=True)
        except sqlite3.Error as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))

        try:
            result = _inspect(connection, parameters)
        except sqlite3.Error as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        finally:
            connection.close()

        return ok(
            AnalysisExecution(
                result=result,
                provider=_PROVIDER,
                limitations=("Row values are only read when a table is explicitly requested.",),
            )
        )


def _inspect(connection: sqlite3.Connection, parameters: dict[str, Any]) -> dict[str, Any]:
    connection.row_factory = sqlite3.Row
    objects = connection.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_master "
        "WHERE type IN ('table','view','index','trigger') ORDER BY type, name"
    ).fetchall()

    tables: list[dict[str, Any]] = []
    indexes: list[dict[str, Any]] = []
    views: list[dict[str, Any]] = []
    triggers: list[dict[str, Any]] = []

    table_name = parameters.get("table")
    row_limit = int(parameters.get("row_limit", 20)) if table_name else 0

    for obj in objects:
        kind = obj["type"]
        entry: dict[str, Any] = {"name": obj["name"], "sql": obj["sql"]}
        if kind == "table":
            entry["columns"] = _columns(connection, obj["name"])
            tables.append(entry)
        elif kind == "index":
            entry["table"] = obj["tbl_name"]
            indexes.append(entry)
        elif kind == "view":
            views.append(entry)
        elif kind == "trigger":
            entry["table"] = obj["tbl_name"]
            triggers.append(entry)

    result: dict[str, Any] = {
        "tables": tables,
        "indexes": indexes,
        "views": views,
        "triggers": triggers,
        "object_count": len(objects),
    }
    if table_name and row_limit > 0:
        result["rows"] = _rows(connection, str(table_name), row_limit)
    return result


def _columns(connection: sqlite3.Connection, table: str) -> list[dict[str, Any]]:
    rows = connection.execute(f"PRAGMA table_info({_quote_ident(table)})").fetchall()
    return [
        {
            "name": row["name"],
            "type": row["type"],
            "notnull": bool(row["notnull"]),
            "primary_key": bool(row["pk"]),
        }
        for row in rows
    ]


def _rows(connection: sqlite3.Connection, table: str, limit: int) -> list[dict[str, Any]]:
    cursor = connection.execute(f"SELECT * FROM {_quote_ident(table)} LIMIT ?", (limit,))
    names = [description[0] for description in cursor.description or []]
    return [dict(zip(names, row, strict=True)) for row in cursor.fetchall()]


def _quote_ident(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


__all__ = ["SqliteDatabaseProvider"]
