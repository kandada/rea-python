from __future__ import annotations

from pathlib import Path

from rea_mcp.application.project_serve import _page, _project_page
from rea_mcp.application.project_store import create_project


def test_project_dashboard_pages(tmp_path: Path) -> None:
    created = create_project(tmp_path / "demo", name="Demo", request="make it")
    assert created.ok
    project = created.value.summary()
    page = _project_page(project)
    assert "Demo" in page and "Checks" in page and "Study" in page
    listing = _page(tmp_path)
    assert "Demo" in listing and "/project?path=" in listing


def test_project_dashboard_escapes_and_renders_inbox(tmp_path: Path) -> None:
    from rea_mcp.application.project_serve import _page, _project_page, _projects
    from rea_mcp.domain.check import CheckResult

    created = create_project(
        tmp_path / "demo", name="<script>", request="<b>build</b>", mode="deep"
    )
    assert created.ok
    store = created.value
    store.save_check(CheckResult("build", 1, False, "<bad>", similarity=12.5))
    store.ask("<question>", options=["<A>"])
    project = store.summary()

    page = _project_page(project)
    assert "&lt;script&gt;" in page
    assert "&lt;b&gt;build&lt;/b&gt;" in page
    assert "&lt;bad&gt;" in page
    assert "Answer" in page

    listing = _page(tmp_path)
    assert "&lt;script&gt;" in listing
    assert "needs work" in listing
    assert _projects(tmp_path)[0]["name"] == "<script>"


def test_project_dashboard_skips_broken_projects(tmp_path: Path) -> None:
    from rea_mcp.application.project_serve import _page, _projects

    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / "project.json").write_text("{bad", encoding="utf-8")
    assert _projects(tmp_path) == []
    page = _page(tmp_path)
    assert "0 project(s)" in page


def test_project_page_without_checks_or_inbox(tmp_path: Path) -> None:
    from rea_mcp.application.project_serve import _project_page

    created = create_project(tmp_path / "empty", name="Empty", request="x")
    assert created.ok
    page = _project_page(created.value.summary())
    assert "empty" in page
    assert "Checks" in page
