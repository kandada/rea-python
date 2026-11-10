from __future__ import annotations

from rea_mcp.domain.check import CheckResult, Claim
from rea_mcp.domain.project import ProjectManifest, new_manifest


def test_manifest_new_targets_and_roundtrip() -> None:
    website = new_manifest(name="Site", request="x", target_path="https://example.com")
    assert website.target["kind"] == "website"
    local = new_manifest(name="App", request="x", target_path="/tmp/app")
    assert local.target["kind"] == "local"
    none = new_manifest(name="Idea", request="x")
    assert none.target["kind"] == "none"
    restored = ProjectManifest.from_dict(website.to_dict())
    assert restored == website


def test_manifest_rejects_newer_version_and_long_name() -> None:
    value = new_manifest(name="x", request="y").to_dict()
    value["version"] = 99
    try:
        ProjectManifest.from_dict(value)
    except ValueError as cause:
        assert "newer" in str(cause)
    else:
        raise AssertionError("newer version was accepted")
    value = new_manifest(name="x" * 200, request="y").to_dict()
    try:
        ProjectManifest.from_dict(value)
    except ValueError as cause:
        assert "too long" in str(cause)
    else:
        raise AssertionError("long name was accepted")


def test_check_result_good_requires_claims_unknowns_and_similarity() -> None:
    good = CheckResult(
        "web-visual",
        1,
        True,
        "ok",
        similarity=95,
        good_enough=90,
        claims=[Claim("loads", True)],
    )
    assert good.good(85) is True
    assert CheckResult.from_dict(good.to_dict()).to_dict() == good.to_dict()
    failed = CheckResult("web", 1, True, claims=[Claim("loads", False, "missing")])
    assert failed.good(85) is False
    unknown = CheckResult("web", 1, True, unknowns=["missing page"])
    assert unknown.good(85) is False
    low = CheckResult("web", 1, True, similarity=50, good_enough=90)
    assert low.good(85) is False
    assert CheckResult.from_dict({"check": "x"}).passed is False
