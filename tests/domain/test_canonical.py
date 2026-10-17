import math

import pytest
from hypothesis import given
from hypothesis import strategies as st

from rea_mcp.domain.canonical import canonical_json, digest_canonical
from rea_mcp.domain.json_value import JsonValueError, normalize_json_value, validate_json_value


def test_key_order_does_not_change_canonical_form() -> None:
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_unicode_is_not_escaped() -> None:
    assert canonical_json({"k": "héllo"}) == '{"k":"héllo"}'


def test_tuple_normalizes_to_list() -> None:
    assert canonical_json((1, 2, 3)) == "[1,2,3]"


def test_nan_and_infinity_are_rejected() -> None:
    with pytest.raises(JsonValueError):
        canonical_json({"x": math.nan})
    with pytest.raises(JsonValueError):
        canonical_json({"x": math.inf})


def test_non_string_keys_are_rejected() -> None:
    with pytest.raises(JsonValueError):
        validate_json_value({1: "a"})


def test_negative_zero_normalizes() -> None:
    assert normalize_json_value(-0.0) == 0.0
    assert canonical_json(-0.0) == "0.0"


@given(
    st.recursive(
        st.none() | st.booleans() | st.integers() | st.text(),
        lambda children: st.lists(children) | st.dictionaries(st.text(), children),
        max_leaves=30,
    )
)
def test_canonical_is_deterministic(value: object) -> None:
    assert canonical_json(value) == canonical_json(value)
    assert digest_canonical(value) == digest_canonical(value)


@given(st.dictionaries(st.text(), st.integers(), min_size=1, max_size=6))
def test_digest_is_insertion_order_independent(mapping: dict[str, int]) -> None:
    reordered = dict(reversed(list(mapping.items())))
    assert digest_canonical(mapping) == digest_canonical(reordered)
