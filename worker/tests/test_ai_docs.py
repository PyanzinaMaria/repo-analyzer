"""LLM-generated documents: marker splitting, payload building, pipeline
integration. Everything is offline — the AI client is a stub."""

from __future__ import annotations

import json
from dataclasses import dataclass
from dataclasses import replace as dc_replace

import pytest

from worker.ai_docs import (
    AiDocError,
    build_combined_markdown,
    build_user_prompt,
    generate_document,
    load_prompt,
    safe_rel_path,
    split_files,
    write_files,
)

SAMPLE_ANSWER = """# ПРОТОКОЛ ИССЛЕДОВАНИЙ

Раздел 1. Общие положения.

ФАЙЛ: attachments/sbom-components.json
```json
{"bomFormat": "CycloneDX"}
```

Раздел 6. Выводы.

ФАЙЛ: docs/README.md
```markdown
# Документация к коду

Назначение проекта.
```
"""


@dataclass(frozen=True)
class _File:
    rel_path: str
    content: str


# ---------------------------------------------------------------- split_files


def test_split_files_extracts_attachments_and_keeps_main():
    main, files = split_files(SAMPLE_ANSWER)
    assert "ПРОТОКОЛ ИССЛЕДОВАНИЙ" in main
    assert "Раздел 6. Выводы." in main
    assert "bomFormat" not in main
    assert [(f.rel_path, f.content) for f in files] == [
        ("attachments/sbom-components.json", '{"bomFormat": "CycloneDX"}'),
        ("docs/README.md", "# Документация к коду\n\nНазначение проекта."),
    ]


def test_split_files_without_markers_returns_whole_answer():
    main, files = split_files("# Просто документ\n\nТекст.")
    assert main == "# Просто документ\n\nТекст."
    assert files == []


def test_split_files_marker_without_block_stays_in_main():
    main, files = split_files("Текст.\n\nФАЙЛ: docs/lost.md\n\nЕщё текст.")
    assert "ФАЙЛ: docs/lost.md" in main
    assert files == []


# ------------------------------------------------------- write_files / paths


def test_safe_rel_path_strips_and_rejects_escapes():
    assert safe_rel_path("docs/README.md") is not None
    assert safe_rel_path("..\\..\\etc\\passwd") is not None  # ".." parts dropped
    assert safe_rel_path("/abs/path/x.json") is not None
    assert safe_rel_path("") is None
    assert safe_rel_path(".") is None
    assert safe_rel_path("..") is None


def test_write_files_persists_under_docs_dir(tmp_path):
    _, files = split_files(SAMPLE_ANSWER)
    written = write_files(files, tmp_path / "docs")
    # The kit's own docs/ segment is stripped; attachments nest normally.
    assert (tmp_path / "docs" / "README.md").read_text(encoding="utf-8").startswith(
        "# Документация к коду"
    )
    assert (tmp_path / "docs" / "attachments" / "sbom-components.json").read_text(
        encoding="utf-8"
    ) == '{"bomFormat": "CycloneDX"}'
    assert len(written) == 2


def test_write_files_sanitizes_escaping_paths(tmp_path):
    files = [_File(rel_path="../outside.md", content="no")]
    written = write_files(files, tmp_path / "docs")
    # The ".." segment is dropped, so the file lands inside the docs dir.
    assert (tmp_path / "docs" / "outside.md").is_file()
    assert not (tmp_path / "outside.md").exists()
    assert len(written) == 1


# --------------------------------------------------- combined markdown builder


def test_combined_markdown_inlines_markdown_and_fences_json():
    main, files = split_files(SAMPLE_ANSWER)
    combined = build_combined_markdown(main, files)
    assert combined.startswith("# ПРОТОКОЛ ИССЛЕДОВАНИЙ")
    assert "## Файл: `attachments/sbom-components.json`" in combined
    assert "```json\n{\"bomFormat\": \"CycloneDX\"}\n```" in combined
    assert "## Файл: `docs/README.md`" in combined
    assert "# Документация к коду" in combined


def test_combined_markdown_rejects_empty_answer():
    with pytest.raises(AiDocError):
        build_combined_markdown("", [])


# ------------------------------------------------------------------ payloads


def test_build_user_prompt_serializes_scan_result(scan_result):
    prompt = build_user_prompt("fstec", scan_result, max_findings=50)
    data = json.loads(prompt)
    assert data["project_name"] == "demo-app"
    assert data["findings"][0]["rule_id"] == "B608"


def test_build_user_prompt_truncates_findings(scan_result):
    prompt = build_user_prompt("fstec", scan_result, max_findings=1)
    data = json.loads(prompt)
    assert len(data["findings"]) == 1
    assert data["meta"]["findings_truncated"] == {"shown": 1, "total": 2}


def test_build_user_prompt_appends_project_files(scan_result):
    prompt = build_user_prompt(
        "codedocs",
        scan_result,
        max_findings=50,
        selected_files=[_File(rel_path="app/main.py", content="print('hi')")],
    )
    assert '<file path="app/main.py">' in prompt
    assert "print('hi')" in prompt


# ------------------------------------------------------------- generation


def _ai_cfg(tmp_path, **overrides):
    """A worker config with ai_documents pointing at a temp prompt file."""
    from worker.config import WorkerConfig

    prompt_file = tmp_path / "prompt.md"
    prompt_file.write_text("Ты технический писатель.", encoding="utf-8")
    specs = overrides.pop(
        "ai_documents",
        {"fstec": {"prompt": str(prompt_file), "timeout_seconds": 5}},
    )
    return WorkerConfig(data_dir=tmp_path / "data", ai_documents=specs, **overrides)


class _StubClient:
    def __init__(self, answer):
        self.answer = answer
        self.calls = []

    def chat(self, system_prompt, user_prompt, **kwargs):
        self.calls.append((system_prompt, user_prompt, kwargs))
        return self.answer


def _stub_settings(max_findings=50):
    from app.ai.config import AiSettings

    return AiSettings(
        enabled=True,
        provider="openai_compatible",
        base_url="http://localhost/v1",
        model="stub",
        api_key="k",
        timeout_seconds=5,
        max_files=5,
        max_file_bytes=1000,
        max_findings=max_findings,
    )


def test_generate_document_combines_and_passes_payload(tmp_path, scan_result):
    cfg = _ai_cfg(tmp_path)
    client = _StubClient(SAMPLE_ANSWER)
    combined, files = generate_document(
        "fstec", scan_result, cfg, client=client, ai_settings=_stub_settings()
    )
    assert "ПРОТОКОЛ ИССЛЕДОВАНИЙ" in combined
    assert len(files) == 2
    system, user, kwargs = client.calls[0]
    assert system == "Ты технический писатель."
    assert kwargs == {}  # json_mode off for documents
    assert '"project_name": "demo-app"' in user


def test_generate_document_requires_spec(tmp_path, scan_result):
    cfg = _ai_cfg(tmp_path)
    with pytest.raises(AiDocError):
        generate_document("codedocs", scan_result, cfg, ai_settings=_stub_settings())


def test_generate_document_requires_prompt_file(tmp_path, scan_result):
    cfg = _ai_cfg(tmp_path, ai_documents={"fstec": {"prompt": "missing/nope.md"}})
    with pytest.raises(AiDocError):
        generate_document("fstec", scan_result, cfg, ai_settings=_stub_settings())


def test_load_prompt_resolves_repo_paths():
    prompt = load_prompt("system_prompts/FSTEC.md")
    assert "ПРОТОКОЛ ИССЛЕДОВАНИЙ" in prompt or "протокола" in prompt


# ------------------------------------------------------------- pipeline


def _enabled_cfg(cfg, monkeypatch):
    """The scan cfg with ai_documents on for both LLM documents and the
    readiness check stubbed (tests have no API key)."""
    from dataclasses import replace as dc_replace

    from worker.pipeline import Pipeline

    enabled = dc_replace(
        cfg,
        ai_documents_enabled=True,
        ai_documents={
            "fstec": {"prompt": "x.md", "timeout_seconds": 5},
            "codedocs": {"prompt": "x.md", "timeout_seconds": 5},
        },
    )
    monkeypatch.setattr(Pipeline, "_ai_docs_configured", lambda self: True)
    return enabled


def test_pipeline_disabled_by_default_produces_no_llm_artifacts(cfg, make_job, scan_result, monkeypatch):
    from worker.pipeline import Pipeline

    scan_id = "11111111-1111-1111-1111-111111111111"
    make_job(scan_id, {"kind": "zip"})
    pipe = Pipeline(cfg)
    monkeypatch.setattr(pipe, "_analyze", lambda scan_id, source, options: scan_result)
    pipe.process({
        "scan_id": scan_id,
        "source": {"kind": "zip"},
        "options": {"formats": ["html"]},
    })
    manifest = json.loads((cfg.reports_dir / scan_id / "manifest.json").read_text("utf-8"))
    assert manifest["artifacts"] == ["report.html", "doc.html"]
    assert not any(name.startswith(("fstec.", "codedocs.")) for name in manifest["artifacts"])


def test_format_plan_excludes_llm_docs_until_ready(cfg):
    from worker.pipeline import Pipeline

    pipe = Pipeline(cfg)  # ai_documents switch off by default
    plan = pipe._format_plan(["html", "docx"])
    assert not any(name.startswith(("fstec.", "codedocs.")) for name in plan)


def test_format_plan_includes_llm_docs_when_ready(cfg, monkeypatch):
    from worker.pipeline import Pipeline

    monkeypatch.setattr(Pipeline, "_ai_docs_configured", lambda self: True)
    pipe = Pipeline(dc_replace(cfg, ai_documents_enabled=True, ai_documents={"fstec": {}, "codedocs": {}}))
    assert pipe._format_plan(["md", "pdf"]) == [
        "report.md",
        "report.pdf",
        "doc.md",
        "doc.pdf",
        "fstec.md",
        "fstec.pdf",
        "codedocs.zip",
    ]


def test_pipeline_with_ai_docs_produces_artifacts_and_docs_kit(
    cfg, make_job, scan_result, monkeypatch
):
    import zipfile
    from worker.pipeline import Pipeline

    scan_id = "11111111-1111-1111-1111-111111111111"
    make_job(scan_id, {"kind": "zip"})
    pipe = Pipeline(_enabled_cfg(cfg, monkeypatch))
    monkeypatch.setattr(pipe, "_analyze", lambda scan_id, source, options: scan_result)

    def fake_generate(self, doc_id, result, reports_dir):
        main, files = split_files(SAMPLE_ANSWER)
        from worker.ai_docs import write_files

        write_files(files, reports_dir / ("docs" if doc_id == "codedocs" else doc_id))
        return build_combined_markdown(main, files)

    monkeypatch.setattr(Pipeline, "_generate_ai_document", fake_generate)
    pipe.process({"scan_id": scan_id, "source": {"kind": "zip"}, "options": {"formats": ["md"]}})

    reports_dir = cfg.reports_dir / scan_id
    manifest = json.loads((reports_dir / "manifest.json").read_text("utf-8"))
    assert manifest["artifacts"] == ["report.md", "doc.md", "fstec.md", "codedocs.zip"]
    assert (reports_dir / "fstec.md").stat().st_size > 0
    with zipfile.ZipFile(reports_dir / "codedocs.zip") as archive:
        assert "README.md" in archive.namelist()
    # Attached files land under docs/ (the kit's own docs/ prefix stripped).
    assert (reports_dir / "docs" / "README.md").is_file()
    assert (reports_dir / "docs" / "attachments" / "sbom-components.json").is_file()
    summary = json.loads((reports_dir / "summary.json").read_text("utf-8"))
    assert summary["documents"] == {"fstec": "ok", "codedocs": "ok"}
    assert manifest["stages"] == {"analysis": "ok", "report": "ok"}


def test_pipeline_ai_doc_failure_is_soft(cfg, make_job, scan_result, monkeypatch):
    import zipfile
    from dataclasses import replace as dc_replace

    from worker.pipeline import Pipeline

    scan_id = "11111111-1111-1111-1111-111111111111"
    make_job(scan_id, {"kind": "zip"})
    enabled = dc_replace(
        cfg,
        ai_documents_enabled=True,
        ai_documents={"fstec": {"prompt": "x.md"}, "codedocs": {"prompt": "x.md"}},
    )
    monkeypatch.setattr(Pipeline, "_ai_docs_configured", lambda self: True)
    pipe = Pipeline(enabled)
    monkeypatch.setattr(pipe, "_analyze", lambda scan_id, source, options: scan_result)

    def boom(self, doc_id, result, reports_dir):
        raise AiDocError("LLM unreachable")

    monkeypatch.setattr(Pipeline, "_generate_ai_document", boom)
    # Mock markdown_to_html to avoid missing package
    import worker.formats as formats_module
    monkeypatch.setattr(formats_module, "markdown_to_html", lambda text: text.replace('\n', '<br>'))
    pipe.process({"scan_id": scan_id, "source": {"kind": "zip"}})

    reports_dir = cfg.reports_dir / scan_id
    manifest = json.loads((reports_dir / "manifest.json").read_text("utf-8"))
    # Report stage still ok (soft failure - pipeline doesn't crash)
    assert manifest["stages"] == {"analysis": "ok", "report": "ok"}
    # Placeholder artifacts ARE produced so download buttons appear
    assert any(name.startswith("fstec.") for name in manifest["artifacts"])
    # Placeholder document is generated (not failed)
    summary = json.loads((reports_dir / "summary.json").read_text("utf-8"))
    assert summary["documents"] == {"fstec": "placeholder", "codedocs": "placeholder"}
    # Placeholder content explains the issue
    fstec_html = (reports_dir / "fstec.html").read_text("utf-8")
    assert "LLM unreachable" in fstec_html
    assert "AI_API_KEY" in fstec_html
    assert "codedocs.zip" in manifest["artifacts"]
    with zipfile.ZipFile(reports_dir / "codedocs.zip") as archive:
        assert "LLM unreachable" in archive.read("README.md").decode("utf-8")
