import pytest

from rea_mcp.domain.result import err, ok, unwrap, unwrap_err


def test_ok_carries_a_value() -> None:
    result = ok(42)
    assert result.ok is True
    assert result.value == 42
    assert unwrap(result) == 42


def test_err_carries_an_error() -> None:
    result = err("boom")
    assert result.ok is False
    assert result.error == "boom"
    assert unwrap_err(result) == "boom"


def test_value_on_error_raises() -> None:
    with pytest.raises(ValueError):
        _ = err("nope").value


def test_error_on_ok_raises() -> None:
    with pytest.raises(ValueError):
        _ = ok(1).error


def test_ok_with_none_value_is_valid() -> None:
    result = ok(None)
    assert result.ok
    assert result.value is None
