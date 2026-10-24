from __future__ import annotations

from rea_mcp.domain.environment_state_rules import (
    all_lines,
    at,
    changes_state,
    collection_match,
    collection_path_of,
    format_item_count,
    identity_candidates,
    is_query_post,
    is_state_write,
    last_segment_value,
    lists_all,
    locate_item,
    locate_list,
    normalized_path,
    pointer_to,
    render_state_list,
    replace_at,
    segments_of,
    selected_collection,
)


def test_path_and_collection_rules() -> None:
    assert segments_of("/api/items/") == ["api", "items"]
    assert normalized_path("/api//items/") == "/api//items"
    assert last_segment_value("/api/items/book%31") == "book1"
    segments = [
        {"text": "api", "supplied": False},
        {"text": "items", "supplied": False},
        {"text": "42", "supplied": True},
    ]
    assert collection_match("/api/items/42", segments) == 1
    assert selected_collection(segments, ["/api/items/42"]) == "/api/items/42"
    assert collection_path_of({"path": "/api/items/42"}, True) == "/api/items"


def test_write_detection() -> None:
    assert changes_state("POST", "/api/items")
    assert not changes_state("POST", "/api/items/search")
    assert is_query_post("POST", "/api/search")
    assert is_state_write({"method": "DELETE", "path": "/api/items/1", "status": 204})
    assert not is_state_write({"method": "DELETE", "path": "/api/items/1", "status": 500})


def test_json_pointer_and_locate() -> None:
    body = {"items": [{"id": "a"}, {"id": "b"}], "count": 2, "name": "x"}
    assert at(body, pointer_to("name")) == "x"
    nested = {"data": {"items": [{"id": "a"}], "meta": {"count": 1}}}
    assert at(nested, "/data/items/0/id") == "a"
    assert at(nested, "/data/meta/count") == 1
    assert at(nested, "/data/missing") is None
    assert at(nested, "/data/items/9") is None
    assert at(nested, "/data/items/x") is None
    assert replace_at(body, pointer_to("name"), "y")["name"] == "y"
    assert locate_item({"id": "a", "name": "n"}, "a") == {"pointer": "", "keys": ["id"]}
    assert locate_list({"data": [{"id": "a"}, {"id": "b"}]}, "id") == "/data"
    assert identity_candidates([{"id": "a"}, {"id": "b"}]) == ["id"]


def test_render_list_updates_only_matching_counter() -> None:
    body = {"items": [{"id": "a"}, {"id": "b"}], "count": 2, "total": "02"}
    view = {"pointer": "/items", "counters": ["count", "total"]}
    rendered = render_state_list(view, body, [{"id": "a"}])
    assert rendered["items"] == [{"id": "a"}]
    assert rendered["count"] == 1
    assert rendered["total"] == "01"
    assert format_item_count(3, "02") == "03"


def test_list_membership_helpers() -> None:
    all_view = {"membership": "all", "checked_record_ordinals": [1, 2]}
    recorded = {"membership": "recorded", "all_record_ordinals": [2]}
    assert lists_all(all_view, 1)
    assert not lists_all(recorded, 1)
    assert all_lines(all_view) == [1, 2]
    assert all_lines(recorded) == [2]
