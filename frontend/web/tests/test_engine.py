"""Form engine tests: config-driven rendering and validation."""

from __future__ import annotations

from app.core.config import get_settings, reload_settings
from app.ui.engine import Form


def setup_function(_):
    reload_settings()


def base_raw(**overrides) -> dict:
    """A valid submission payload; individual tests override fields."""
    raw = {
        "source_kind": "link",
        "repo_url": "https://github.com/owner/repo",
        "methods": ["sast"],
        "formats": ["md"],
    }
    raw.update(overrides)
    return raw


def test_form_loaded_from_config():
    form = Form(get_settings())
    assert form.spec.id == "audit"
    assert any(f.name == "repo_url" for f in form.spec.fields)


def test_url_host_allowlist():
    form = Form(get_settings())
    _, errors = form.validate(base_raw(repo_url="https://evil.com/x"))
    assert "repo_url" in errors

    clean, errors = form.validate(base_raw())
    assert not errors
    assert clean["repo_url"] == "https://github.com/owner/repo"


def test_required_files_when_kind_files():
    form = Form(get_settings())
    _, errors = form.validate(base_raw(source_kind="files", repo_url=""), files=[])
    assert "files" in errors

    upload = object()
    _, errors = form.validate(base_raw(source_kind="files", repo_url=""), files=[upload])
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
    _, errors = form.validate(base_raw(source_kind="git"))
    assert "source_kind" in errors


def test_choices_from_resolved_from_analysis_config():
    """The methods field pulls its options from analysis.yaml — including the
    disabled marker for methods that are not available yet."""
    form = Form(get_settings())
    field = form.field("methods")
    values = {c["value"] for c in field.choices}
    assert {"sast", "llm_agentic", "dast", "pentest"} <= values
    disabled = {c["value"] for c in field.choices if c.get("disabled")}
    assert disabled == {"pentest"}
    assert "dast" in {c["value"] for c in field.choices}
    assert "dast" not in disabled
    assert field.default == ["sast"]  # defaults_from analysis.defaults.methods


def test_multi_validation_rejects_unknown_and_disabled():
    form = Form(get_settings())
    _, errors = form.validate(base_raw(methods=["sast", "tarot"]))
    assert "methods" in errors  # unknown -> bad_choice

    _, errors = form.validate(base_raw(methods=["sast", "pentest"]))
    assert errors["methods"].key == "errors.unavailable_choice"  # planned -> rejected

    clean, errors = form.validate(base_raw(methods=["sast", "dast", "llm_agentic"]))
    assert not errors
    assert clean["methods"] == ["sast", "dast", "llm_agentic"]
