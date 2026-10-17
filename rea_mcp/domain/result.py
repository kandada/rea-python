"""Typed success/failure channel used throughout REA-Python.

REA-Python deliberately avoids raising exceptions for *expected* failures. Operations
return a :class:`Result` so that partial facts and meaningful failure reasons can
be preserved across boundaries, mirroring REA's ``Result<T, E>``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, TypeVar, Union

T = TypeVar("T")
E = TypeVar("E")


@dataclass(frozen=True, slots=True)
class Result(Generic[T, E]):
    """A tagged result: either ``ok=True`` with a value, or ``ok=False`` with an error."""

    ok: bool
    _value: T | None = None
    _error: E | None = None

    @property
    def value(self) -> T:
        if not self.ok:
            raise ValueError("Result has no value (ok=False)")
        assert self._value is not None or _is_none_value(self._value)
        return self._value  # type: ignore[return-value]

    @property
    def error(self) -> E:
        if self.ok:
            raise ValueError("Result has no error (ok=True)")
        return self._error  # type: ignore[return-value]


def _is_none_value(value: object) -> bool:
    return value is None


def ok(value: T) -> Result[T, E]:
    """Construct a successful result."""

    return Result(ok=True, _value=value, _error=None)


def err(error: E) -> Result[T, E]:
    """Construct a failed result."""

    return Result(ok=False, _value=None, _error=error)


def is_ok(result: Result[T, E]) -> bool:
    return result.ok


def is_err(result: Result[T, E]) -> bool:
    return not result.ok


def unwrap(result: Result[T, E]) -> T:
    """Return the value or raise the error (for tests and trusted call sites)."""

    if not result.ok:
        error = result.error
        if isinstance(error, BaseException):
            raise error
        raise ValueError(f"Result is an error: {error!r}")
    return result.value


def unwrap_err(result: Result[T, E]) -> E:
    if result.ok:
        raise ValueError("Result is ok, expected an error")
    return result.error


def map_result(result: Result[T, E], fn: object) -> Result[object, E]:
    """Map a successful value. Kept intentionally small; prefer explicit branches."""

    if not result.ok:
        return err(result.error)
    return ok(fn(result.value))  # type: ignore[operator]


__all__ = ["Result", "Union", "err", "is_err", "is_ok", "ok", "unwrap", "unwrap_err"]
