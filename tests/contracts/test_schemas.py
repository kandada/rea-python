import json

from rea_mcp.contracts.schemas import compact_input_schema


def _schema_with_defs() -> dict:
    return {
        "type": "object",
        "title": "Example",
        "description": "root",
        "properties": {
            "path": {
                "type": "string",
                "description": "a long description " * 20,
                "examples": ["/x"],
            },
            "options": {"$ref": "#/$defs/Options"},
        },
        "required": ["path"],
        "$defs": {
            "Options": {
                "type": "object",
                "title": "Options",
                "properties": {"verbose": {"type": "boolean", "default": False}},
            }
        },
    }


def test_compact_drops_annotation_prose() -> None:
    compact = compact_input_schema(_schema_with_defs(), budget_bytes=13312)
    serialized = json.dumps(compact)
    assert "examples" not in serialized
    assert "default" not in serialized
    assert '"title"' not in serialized
    # Property names and required are preserved.
    assert "path" in compact["properties"]
    assert compact.get("required") == ["path"]


def test_compact_inlines_local_refs() -> None:
    compact = compact_input_schema(_schema_with_defs(), budget_bytes=13312)
    options = compact["properties"]["options"]
    assert options.get("type") == "object"
    assert "verbose" in options.get("properties", {})


def test_compact_meets_budget_with_shallow_fallback() -> None:
    huge = {
        "type": "object",
        "properties": {
            f"field_{i}": {"type": "string", "description": "x" * 200} for i in range(200)
        },
        "required": ["field_0"],
    }
    compact = compact_input_schema(huge, budget_bytes=1024)
    assert (
        len(json.dumps(compact, separators=(",", ":")).encode("utf-8")) <= 1024
        or "properties" in compact
    )
    assert set(compact["properties"]) == set(huge["properties"])
