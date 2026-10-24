from __future__ import annotations

from rea_mcp.domain.environment_state_rules import (
    all_lines,
    api_base_lengths,
    collection_match,
    deeper_than,
    has_prototype_key,
    is_projection_parameter,
    lists_all,
    missing_required_fields,
    projects_fields,
    render_state_entity,
    render_state_list,
    replace_at,
    respell_clock,
    root_of,
    selected_collection,
    state_value_retention_bytes,
    write_span_check,
)


def test_write_span_check_uses_ordered_windows() -> None:
    check = write_span_check(
        [
            {"start": 0, "end": 10},
            {"start": 5, "end": 20},
            {"start": 30, "end": 40},
        ]
    )
    assert check({"start": 12}, {"end": 25})
    assert not check({"start": 25}, {"end": 28})
    assert check({"start": 35}, {"end": 39})


def test_api_base_lengths_and_root_of() -> None:
    bases = api_base_lengths(["/api/v1/items/{id}", "/api/v1/users/{id}", "/health"])
    assert bases["api"] == 2
    assert bases["health"] == 1
    assert root_of("/api/v1/items/1", bases) == ["api", "v1", "items"]
    assert root_of("/health", bases) == ["health"]


def test_retention_depth_and_prototype_rules() -> None:
    value = {"a": [1, {"b": "xx"}]}
    assert state_value_retention_bytes(value) > 0
    assert deeper_than(value, 0)
    assert not deeper_than(value, 5)
    assert has_prototype_key({"a": [{"__proto__": 1}]})
    assert not has_prototype_key({"a": [{"b": 1}]})


def test_collection_match_and_selection_prefers_verbatim() -> None:
    segments = [
        {"text": "api", "supplied": False},
        {"text": "items", "supplied": True},
        {"text": "1", "supplied": True},
    ]
    assert collection_match("/api/items/1", segments) == 2
    assert collection_match("/api/items/1", [{**segments[0], "supplied": True}, *segments[1:]]) == 3
    assert collection_match("/api/other/1", segments) is None
    assert selected_collection(segments, ["/api/items/1", "/api/items/2"]) == "/api/items/1"
    assert selected_collection(segments, []) == "/api/items/1"


def test_nested_replace_at_preserves_structure() -> None:
    body = {"data": {"items": [{"id": "a"}], "meta": {"count": 1}}, "keep": True}
    replaced = replace_at(body, "/data/items", [{"id": "b"}])
    assert replaced["data"]["items"] == [{"id": "b"}]
    assert replaced["data"]["meta"] == {"count": 1}
    assert replaced["keep"] is True
    assert replace_at(body, "/data/missing", 1) is body
    assert replace_at(body, "", {"x": 1}) == {"x": 1}


def test_render_entity_list_and_missing_fields() -> None:
    entity = {
        "type": "/api/items/{id}",
        "fields": {"id": "1", "name": "one", "clock": "old"},
        "view_fields": [{"tool": "get", "fields": {"id": "1", "name": "one", "clock": "old"}}],
    }
    view = {"tool": "get", "fields": ["id", "name", "clock"], "required_fields": ["id", "name"]}
    assert render_state_entity(entity, view, set()) == {
        "id": "1",
        "name": "one",
        "clock": "old",
    }
    assert render_state_entity(entity, view, {"clock"}, {"clock": "new"})["clock"] == "new"
    assert missing_required_fields({"fields": {"id": "1"}}, view, set()) == ["name"]
    body = {"items": [{"id": "a"}, {"id": "b"}], "count": 2, "total": "02"}
    rendered = render_state_list(
        {"pointer": "/items", "counters": ["count", "total"]}, body, [{"id": "a"}]
    )
    assert rendered["items"] == [{"id": "a"}]
    assert rendered["count"] == 1
    assert rendered["total"] == "01"


def test_projection_and_membership_helpers() -> None:
    assert is_projection_parameter("fields")
    assert is_projection_parameter("$select")
    assert projects_fields("?fields=id&fields=name")
    assert projects_fields("?select=id")
    assert not projects_fields("?limit=1")
    view = {"membership": "all", "checked_record_ordinals": [1, 2]}
    assert lists_all(view, 9)
    assert all_lines(view) == [1, 2]
    assert not lists_all({"membership": "partial"}, 9)
    assert respell_clock("2020", "x") == "2020"


def test_same_handles_none_and_non_json_values() -> None:
    from rea_mcp.domain.environment_state_rules import same

    assert same(None, None)
    assert not same(None, {})
    assert same({"a": 1}, {"a": 1})
    assert not same({"a": 1}, {"a": 2})
    assert not same({"a": float("nan")}, {"a": float("nan")})


def test_collection_match_requires_equal_length_and_verbatim_unsupplied() -> None:
    assert collection_match("/api/items", [{"text": "api"}]) is None
    assert collection_match("/api/items", [{"text": "api"}, {"text": "nope"}]) is None
    assert collection_match("/api/items", [{"text": "api"}, {"text": "ITEM"}]) is None
    assert collection_match("/api/items", [{"text": "api"}, {"text": "items"}]) == 0


def test_root_of_consumes_version_segments() -> None:
    bases = {"api": 1}
    assert root_of("/api/v1/v2/items", bases) == ["api", "v1", "v2", "items"]
    assert root_of("/", {}) == []


def test_at_and_replace_at_scalar_and_missing_branches() -> None:
    from rea_mcp.domain.environment_state_rules import at

    assert at({"a": [1, 2]}, "/a/1") == 2
    assert at("scalar", "/a") is None
    assert replace_at({"a": [1]}, "/a/3", 9) == {"a": [1]}
    assert replace_at({"a": [1]}, "/a/x", 9) == {"a": [1]}
    assert replace_at({"a": [1]}, "/a/0", 9) == {"a": [9]}
    assert replace_at([1, 2], "/1", 9) == [1, 9]


def test_identity_suffix_and_root_list_locate() -> None:
    from rea_mcp.domain.environment_state_rules import (
        identity_candidates,
        locate_list,
    )

    assert identity_candidates([{"itemId": "a"}, {"itemId": "b"}]) == ["itemId"]
    assert locate_list([{"id": "a"}], None) == ""
    assert locate_list([1], None) is None
    assert locate_list({"id": "a", "items": [{"id": "a"}]}, None) is None


def test_recorded_count_and_counter_skip() -> None:
    from rea_mcp.domain.environment_state_rules import recorded_item_count

    assert recorded_item_count(2) == 2
    assert recorded_item_count("02") == 2
    assert recorded_item_count(True) is None
    assert recorded_item_count("x") is None
    body = {"items": [{"id": "a"}, {"id": "b"}], "count": 99}
    rendered = render_state_list({"pointer": "/items", "counters": ["count"]}, body, [{"id": "a"}])
    assert rendered["count"] == 99
