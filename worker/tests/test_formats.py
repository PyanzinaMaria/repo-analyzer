"""Format handlers: markdown reuse, html converters, lazy imports."""

from __future__ import annotations

import pytest

from worker.formats import HTML_CONVERTERS, render_document_markdown


def test_markdown_handlers_render_documents(scan_result, tmp_path):
    report_md = tmp_path / "report.md"
    doc_md = tmp_path / "doc.md"
    render_document_markdown("report", scan_result, report_md)
    render_document_markdown("doc", scan_result, doc_md)

    assert report_md.stat().st_size > 0
    assert doc_md.stat().st_size > 0
    assert "SQL-инъекция" in report_md.read_text(encoding="utf-8")
    assert "ФСТЭК" in doc_md.read_text(encoding="utf-8")


def test_markdown_unknown_document_raises(scan_result, tmp_path):
    with pytest.raises(ValueError):
        render_document_markdown("unknown", scan_result, tmp_path / "x.md")


def test_docx_converter():
    pytest.importorskip("htmldocx")
    html = "<h1>Отчёт</h1><p>Найдено: SQL-инъекция</p>"
    data = HTML_CONVERTERS["docx"](html)
    assert data[:2] == b"PK"  # docx is a zip container


def test_pdf_converter():
    pytest.importorskip("weasyprint")
    html = "<h1>Отчёт</h1><p>Проверка PDF</p>"
    data = HTML_CONVERTERS["pdf"](html)
    assert data[:5] == b"%PDF-"
