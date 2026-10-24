"""Pure rules shared by environment state extraction, replay and rendering.

Ported from upstream ``environmentStateRules``. Values are ordinary JSON
dicts/lists/scalars; the module deliberately has no CLI or Evidence dependency.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs, quote, unquote

JsonValue = Any
JsonObject = dict[str, JsonValue]
StateType = dict[str, Any]
StateEntity = dict[str, Any]
StateDocument = dict[str, Any]
StateView = dict[str, Any]
StateWritePlan = dict[str, Any]
ListQuery = dict[str, Any]

STATE_BODY_LIMIT_BYTES = 256 * 1024
ENTRY_BYTES = 8
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
QUERY_SEGMENTS = {
    "search",
    "query",
    "list",
    "find",
    "fuzzy",
    "lookup",
    "count",
    "aggregate",
    "stats",
    "_search",
    "_count",
    "_msearch",
}
IDENTITY_NAMES = ["id", "uid", "uuid", "_id", "ID", "UID", "Id", "guid", "key", "slug", "name"]
VERSION_SEGMENT = re.compile(r"^v\d+(?:\.\d+)*$")
IDENTITY_SUFFIX = re.compile(r"(?:Id|_id)$")


def canonical_json(value: JsonValue) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def text_bytes(length: int) -> int:
    return length


def segments_of(path: str) -> list[str]:
    segments = path.split("/")
    if segments and segments[0] == "":
        segments.pop(0)
    if segments and segments[-1] == "":
        segments.pop()
    return segments


def is_param(segment: str) -> bool:
    return segment.startswith("{") and segment.endswith("}")


def is_object(value: JsonValue) -> bool:
    return isinstance(value, dict)


def scalar_text(value: JsonValue) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return None


def same(left: JsonValue, right: JsonValue) -> bool:
    if left is None or right is None:
        return left is right
    try:
        return canonical_json(left) == canonical_json(right)
    except (TypeError, ValueError):
        return False


def decoded_segment(segment: str) -> str:
    try:
        return unquote(segment)
    except Exception:
        return segment


def path_segment_matches(segment: str, value: str) -> bool:
    return (
        segment == value or decoded_segment(segment) == value or decoded_segment(value) == segment
    )


def collection_match(collection: str, segments: list[dict[str, Any]]) -> int | None:
    held = segments_of(collection)
    if len(held) != len(segments):
        return None
    verbatim = 0
    for index, segment in enumerate(segments):
        text = str(segment.get("text", ""))
        supplied = bool(segment.get("supplied"))
        if supplied:
            if not path_segment_matches(held[index], text):
                return None
            if held[index] == text:
                verbatim += 1
        elif held[index] != text:
            return None
    return verbatim


def selected_collection(segments: list[dict[str, Any]], candidates: list[str]) -> str:
    chosen = None
    best = -1
    for collection in candidates:
        matched = collection_match(collection, segments)
        if matched is not None and matched > best:
            chosen = collection
            best = matched
    if chosen is not None:
        return chosen
    return "/" + "/".join(
        quote(str(segment.get("text", "")), safe="")
        if segment.get("supplied")
        else str(segment.get("text", ""))
        for segment in segments
    )


def last_segment_value(path: str) -> str:
    segments = segments_of(path)
    return decoded_segment(segments[-1]) if segments else ""


def normalized_path(path: str) -> str:
    return "/" + "/".join(segments_of(path))


def collection_path_of(record: dict[str, Any], item: bool) -> str:
    path = str(record.get("path", ""))
    segments = segments_of(path)
    if item:
        segments = segments[:-1]
    return "/" + "/".join(segments)


def is_query_post(method: str, path: str) -> bool:
    return method == "POST" and any(
        segment.lower() in QUERY_SEGMENTS for segment in segments_of(path)
    )


def changes_state(method: str, path: str) -> bool:
    return method in WRITE_METHODS and not is_query_post(method, path)


def is_state_write(record: dict[str, Any]) -> bool:
    status = record.get("status")
    method = str(record.get("method", ""))
    path = str(record.get("path", ""))
    return changes_state(method, path) and (
        status is None or (isinstance(status, int) and 200 <= status < 400)
    )


def write_span_check(
    writes: list[dict[str, Any]],
) -> Callable[[dict[str, Any], dict[str, Any]], bool]:
    reach: list[float] = []
    for write in writes:
        reach.append(max(reach[-1] if reach else float("-inf"), float(write.get("end", 0))))

    def check(earlier: dict[str, Any], later: dict[str, Any]) -> bool:
        low, high = 0, len(writes)
        while low < high:
            middle = (low + high) // 2
            if float(writes[middle].get("start", 0)) < float(later.get("end", 0)):
                low = middle + 1
            else:
                high = middle
        return low > 0 and reach[low - 1] > float(earlier.get("start", 0))

    return check


def api_base_lengths(templates: list[str]) -> dict[str, int]:
    groups: dict[str, list[list[str]]] = {}
    for template in templates:
        segments = segments_of(template)
        first = segments[0] if segments else ""
        groups.setdefault(first, []).append(segments)
    result: dict[str, int] = {}
    for first, members in groups.items():
        head = members[0] if members else []
        length = 0
        while (
            length < len(head)
            and not is_param(head[length])
            and all(
                length < len(segments) and segments[length] == head[length] for segments in members
            )
        ):
            length += 1
        result[first] = length
    return result


def root_of(path: str, bases: dict[str, int]) -> list[str]:
    segments = segments_of(path)
    end = min(bases.get(segments[0] if segments else "", 0), len(segments))
    while end < len(segments) and VERSION_SEGMENT.match(segments[end]):
        end += 1
    return segments[: end + 1]


def state_value_retention_bytes(value: JsonValue) -> int:
    if isinstance(value, str):
        return text_bytes(len(value))
    if isinstance(value, list):
        return sum(state_value_retention_bytes(item) for item in value) + ENTRY_BYTES
    if is_object(value):
        return (
            sum(
                text_bytes(len(name)) + state_value_retention_bytes(item)
                for name, item in value.items()
            )
            + ENTRY_BYTES
        )
    return ENTRY_BYTES


def deeper_than(value: JsonValue, limit: int) -> bool:
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > limit:
            return True
        children = (
            item if isinstance(item, list) else list(item.values()) if is_object(item) else []
        )
        pending.extend((child, depth + 1) for child in children)
    return False


def has_prototype_key(value: JsonValue) -> bool:
    if isinstance(value, list):
        return any(has_prototype_key(item) for item in value)
    return is_object(value) and any(
        name == "__proto__" or has_prototype_key(item) for name, item in value.items()
    )


def pointer_to(name: str) -> str:
    return "/" + name.replace("~", "~0").replace("/", "~1")


def pointer_tokens(pointer: str) -> list[str]:
    if pointer == "":
        return []
    return [token.replace("~1", "/").replace("~0", "~") for token in pointer[1:].split("/")]


def at(body: JsonValue, pointer: str) -> JsonValue:
    current: JsonValue = body
    for token in pointer_tokens(pointer):
        if is_object(current):
            if token not in current:
                return None
            current = current[token]
        elif isinstance(current, list):
            if not token.isdigit():
                return None
            index = int(token)
            if index < 0 or index >= len(current):
                return None
            current = current[index]
        else:
            return None
    return current


def replace_at(body: JsonValue, pointer: str, value: JsonValue) -> JsonValue:
    tokens = pointer_tokens(pointer)
    if not tokens:
        return value

    def replace(current: JsonValue, index: int) -> JsonValue:
        token = tokens[index]
        last = index == len(tokens) - 1
        if is_object(current):
            if token not in current:
                return current
            updated_object = dict(current)
            updated_object[token] = value if last else replace(current[token], index + 1)
            return updated_object
        if isinstance(current, list):
            if not token.isdigit():
                return current
            position = int(token)
            if position < 0 or position >= len(current):
                return current
            updated_list = list(current)
            updated_list[position] = value if last else replace(current[position], index + 1)
            return updated_list
        return current

    if at(body, pointer) is None:
        return body
    return replace(body, 0)


def _matching_keys(obj: JsonObject, value: str) -> list[str]:
    return [key for key, item in obj.items() if scalar_text(item) == value]


def locate_item(body: JsonValue, value: str) -> dict[str, Any] | None:
    def located(obj: JsonValue, pointer: str, named: bool = False) -> list[dict[str, Any]]:
        keys = _matching_keys(obj, value) if is_object(obj) else []
        if named:
            keys = [key for key in keys if key in IDENTITY_NAMES]
        return [{"pointer": pointer, "keys": keys}] if keys else []

    members = list(body.items()) if is_object(body) else []
    sole = body[0] if isinstance(body, list) and len(body) == 1 else None
    tiers = [
        located(body, ""),
        [entry for name, item in members for entry in located(item, pointer_to(name))],
        located(sole, "/0", True),
        [
            entry
            for name, item in members
            for entry in located(
                item[0] if isinstance(item, list) and len(item) == 1 else None,
                f"{pointer_to(name)}/0",
                True,
            )
        ],
    ]
    for tier in tiers:
        if tier:
            return tier[0] if len(tier) == 1 else None
    return None


def identifies(items: list[JsonObject], name: str) -> bool:
    seen: set[str] = set()
    for item in items:
        value = scalar_text(item.get(name))
        if value is None or value in seen:
            return False
        seen.add(value)
    return True


def identity_candidates(items: list[JsonObject]) -> list[str]:
    names = [name for name in IDENTITY_NAMES if identifies(items, name)]
    if items:
        names += [
            name
            for name in items[0]
            if IDENTITY_SUFFIX.search(name)
            and name not in IDENTITY_NAMES
            and identifies(items, name)
        ]
    return names


def locate_list(body: JsonValue, id_field: str | None) -> str | None:
    if isinstance(body, list):
        return "" if all(is_object(item) for item in body) else None
    if not is_object(body) or any(
        scalar_text(body.get(name)) is not None for name in IDENTITY_NAMES
    ):
        return None
    arrays = [
        (name, items)
        for name, items in body.items()
        if isinstance(items, list) and all(is_object(item) for item in items)
    ]
    if id_field is None:
        tiers = [
            [
                (name, items)
                for name, items in arrays
                if items and any(identifies(items, identity) for identity in IDENTITY_NAMES)
            ],
            [
                (name, items)
                for name, items in arrays
                if len(items) > 1 and identity_candidates(items)
            ],
            arrays,
        ]
    else:
        tiers = [[(name, items) for name, items in arrays if identifies(items, id_field)], arrays]
    for tier in tiers:
        if tier:
            return pointer_to(tier[0][0]) if len(tier) == 1 else None
    return None


def list_items(body: JsonValue, pointer: str) -> list[JsonObject] | None:
    value = at(body, pointer)
    return value if isinstance(value, list) and all(is_object(item) for item in value) else None


def recorded_item_count(value: JsonValue) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def format_item_count(count: int, observed: JsonValue) -> JsonValue:
    return str(count).zfill(len(observed)) if isinstance(observed, str) else count


def render_state_entity(
    entity: StateEntity,
    view: dict[str, Any],
    volatile_fields: set[str],
    observed: JsonObject | None = None,
) -> JsonObject:
    own: JsonObject = next(
        (
            item.get("fields", {})
            for item in entity.get("view_fields", [])
            if item.get("tool") == view.get("tool")
        ),
        {},
    )
    rendered: JsonObject = {}
    for name in view.get("fields", []):
        source = (
            observed
            if observed is not None and name in volatile_fields
            else own
            if name in own
            else entity.get("fields", {})
        )
        if name in source:
            rendered[name] = source[name]
    return rendered


def missing_required_fields(
    entity: StateEntity, view: dict[str, Any], volatile_fields: set[str]
) -> list[str]:
    shown = render_state_entity(entity, view, volatile_fields)
    return [name for name in view.get("required_fields", []) if name not in shown]


def render_state_list(view: dict[str, Any], base: JsonValue, items: list[JsonObject]) -> JsonValue:
    listed = list_items(base, view.get("pointer", ""))
    body = replace_at(base, view.get("pointer", ""), items)
    for name in view.get("counters", []):
        observed = at(base, pointer_to(name))
        if listed is None or recorded_item_count(observed) != len(listed):
            continue
        body = replace_at(body, pointer_to(name), format_item_count(len(items), observed))
    return body


def is_projection_parameter(name: str) -> bool:
    lower = name.lower()
    return lower == "fields" or lower.startswith("fields[") or lower in ("select", "$select")


def projects_fields(query: str | None) -> bool:
    return bool(
        query and any(is_projection_parameter(name) for name in parse_qs(query.lstrip("?")))
    )


def lists_all(view: dict[str, Any], ordinal: int) -> bool:
    return view.get("membership") == "all" or ordinal in (view.get("all_record_ordinals") or [])


def all_lines(view: dict[str, Any]) -> list[int]:
    return (
        list(view.get("checked_record_ordinals") or [])
        if view.get("membership") == "all"
        else list(view.get("all_record_ordinals") or [])
    )


def respell_clock(value: Any, _format: Any) -> Any:
    """Clock spelling is preserved for now; the state model does not reinterpret stored clocks."""
    return value


__all__ = [name for name in globals() if not name.startswith("_")]
