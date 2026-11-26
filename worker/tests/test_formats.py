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
    # Windows uses xhtml2pdf; Linux/Docker prefer WeasyPrint. Either engine
    # satisfies the converter contract.
    pytest.importorskip("xhtml2pdf")
    html = "<html><head></head><body><h1>Отчёт</h1><p>Проверка PDF</p></body></html>"
    data = HTML_CONVERTERS["pdf"](html)
    assert data[:5] == b"%PDF-"
    assert len(data) > 1000  # embedded font for Cyrillic on Windows


def test_prepare_html_for_pdf_keeps_table_rows():
    from worker.formats import _prepare_html_for_pdf

    html = (
        '<table style="overflow: hidden;">'
        '<tr><th>Уровень</th></tr>'
        '<tr><td><span class="badge" style="background: #C4A1FF;">Высокий</span></td>'
        "<td>SQL-инъекция</td></tr></table>"
    )
    prepared = _prepare_html_for_pdf(html)
    assert "overflow:visible" in prepared
    assert "SQL-инъекция" in prepared
    assert 'style="background:' not in prepared
    assert prepared.count("<tr>") == 2


def test_markdown_without_attached_files_keeps_protocol():
    from worker.formats import markdown_without_attached_files

    md = (
        "# Протокол\n\nРаздел 1.\n\n"
        "## Файл: `attachments/marking_sao.json`\n\n```json\n{\"verdict\":\"истинное\"}\n```\n"
    )
    out = markdown_without_attached_files(md)
    assert "Протокол" in out
    assert "marking_sao" not in out
    assert "attachments" in out


def test_pdf_renders_cyrillic_inside_code():
    pytest.importorskip("xhtml2pdf")
    pytest.importorskip("pypdf")
    from io import BytesIO

    from pypdf import PdfReader

    from worker.formats import html_to_pdf, markdown_to_html

    html = markdown_to_html(
        '# Заголовок\n\n```json\n{"verdict":"истинное","note":"Подтверждено"}\n```\n'
    )
    pdf = html_to_pdf(html)
    text = "\n".join((page.extract_text() or "") for page in PdfReader(BytesIO(pdf)).pages)
    assert "истинное" in text
    assert "Подтверждено" in text
    assert "■" not in text
