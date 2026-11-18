"""Form engine tests: config-driven rendering and validation."""

from __future__ import annotations

from app.core.config import get_settings, reload_settings
from app.ui.engine import Form


def setup_function(_):
    reload_settings()


def test_form_loaded_from_config():
    form = Form(get_settings())
    assert form.spec.id == "audit"
    assert any(f.name == "repo_url" for f in form.spec.fields)


def test_url_host_allowlist():
    form = Form(get_settings())
    clean, errors = form.validate({"source_kind": "link", "repo_url": "https://evil.com/x"})
    assert "repo_url" in errors

    clean, errors = form.validate({"source_kind": "link", "repo_url": "https://github.com/owner/repo"})
    assert not errors
    assert clean["repo_url"] == "https://github.com/owner/repo"


def test_required_files_when_kind_files():
    form = Form(get_settings())
    _, errors = form.validate({"source_kind": "files", "repo_url": ""}, files=[])
    assert "files" in errors

    upload = object()
    _, errors = form.validate({"source_kind": "files", "repo_url": ""}, files=[upload])
    assert not errors


def test_visibility_by_source_kind():
    form = Form(get_settings())
    visible = form.visible_fields({"source_kind": "files"})
    names = {f.name for f in visible}
    assert "files" in names and "repo_url" not in names

    visible = form.visible_fields({"source_kind": "link"})
    names = {f.name for f in visible}
    assert "repo_url" in names and "files" not in names


def test_bad_choice_rejected():
    form = Form(get_settings())
    _, errors = form.validate({"source_kind": "git", "repo_url": ""})
    assert "source_kind" in errors
