"""Output format handlers.

Each handler converts one document (the analyzer result plus its rendered
HTML) into a serveable artifact. Heavy dependencies are imported lazily
inside the handlers so scans that never ask for pdf/docx run without those
packages installed.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any, Callable


def render_document_markdown(doc_id: str, result: Any, target: Path) -> None:
    """Reuse the analyzer's report services: ``report`` -> security audit
    markdown, ``doc`` -> FSTEC draft markdown."""
    from app.services.report.fstec import render_fstec_draft
    from app.services.report.security import render_security_markdown

    if doc_id == "report":
        render_security_markdown(result, target)
    elif doc_id == "doc":
        render_fstec_draft(result, target)
    else:
        raise ValueError(f"no markdown renderer for document {doc_id!r}")


def html_to_pdf(html: str) -> bytes:
    try:
        from weasyprint import HTML
    except ImportError as exc:  # pragma: no cover - exercised via importorskip
        raise RuntimeError("PDF output requires weasyprint (see worker requirements)") from exc
    return HTML(string=html).write_pdf()


def html_to_docx(html: str) -> bytes:
    try:
        from docx import Document
        from htmldocx import HtmlToDocx
    except ImportError as exc:  # pragma: no cover - exercised via importorskip
        raise RuntimeError("DOCX output requires python-docx + htmldocx (see worker requirements)") from exc
    document = Document()
    HtmlToDocx().add_html_to_document(html, document)
    buffer = io.BytesIO()
    document.save(buffer)
    return buffer.getvalue()


# Converters from a document's rendered HTML to binary artifacts.
HTML_CONVERTERS: dict[str, Callable[[str], bytes]] = {
    "pdf": html_to_pdf,
    "docx": html_to_docx,
}
