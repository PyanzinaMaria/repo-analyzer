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


_CYRILLIC_FONTS = (
    Path(r"C:\Windows\Fonts\arial.ttf"),
    Path(r"C:\Windows\Fonts\segoeui.ttf"),
    Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
    Path("/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf"),
)
_FONT_CACHE = Path(__file__).resolve().parent / "assets" / "fonts" / "DocFont.ttf"


def _ensure_pdf_font() -> Path | None:
    """Copy a system TTF into the worker tree so xhtml2pdf's resource policy
    (paths must stay under the project) can embed Cyrillic glyphs."""
    import shutil

    if _FONT_CACHE.is_file():
        return _FONT_CACHE
    src = next((p for p in _CYRILLIC_FONTS if p.is_file()), None)
    if src is None:
        return None
    _FONT_CACHE.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, _FONT_CACHE)
    return _FONT_CACHE


def _pdf_via_xhtml2pdf(html: str) -> bytes:
    from xhtml2pdf import pisa

    font = _ensure_pdf_font()
    path_base = ""
    if font is not None:
        style = (
            "<style>"
            "@font-face{font-family:DocFont;src:url('DocFont.ttf');}"
            "@font-face{font-family:DocFont;src:url('DocFont.ttf');font-weight:bold;}"
            "*{font-family:DocFont,sans-serif;}"
            "</style>"
        )
        path_base = str(font.parent) + "/"
        lower = html.lower()
        if "<head" in lower:
            idx = lower.index("<head")
            gt = html.index(">", idx) + 1
            html = html[:gt] + style + html[gt:]
        else:
            html = f"<html><head>{style}</head><body>{html}</body></html>"

    buffer = io.BytesIO()
    result = pisa.CreatePDF(html, dest=buffer, encoding="utf-8", path=path_base)
    if result.err:
        raise RuntimeError(f"xhtml2pdf failed to render PDF ({result.err} errors)")
    return buffer.getvalue()


def html_to_pdf(html: str) -> bytes:
    """WeasyPrint on Linux/Docker; xhtml2pdf on Windows (no GTK/Pango)."""
    import sys

    engines: list[tuple[str, Callable[[str], bytes]]] = []
    if sys.platform == "win32":
        engines.append(("xhtml2pdf", _pdf_via_xhtml2pdf))
        engines.append(("weasyprint", _pdf_via_weasyprint))
    else:
        engines.append(("weasyprint", _pdf_via_weasyprint))
        engines.append(("xhtml2pdf", _pdf_via_xhtml2pdf))

    errors: list[BaseException] = []
    for _name, engine in engines:
        try:
            return engine(html)
        except Exception as exc:  # noqa: BLE001 — try the next engine
            errors.append(exc)
    raise RuntimeError(
        "PDF output requires weasyprint (with GTK/Pango) or xhtml2pdf"
    ) from (errors[-1] if errors else None)


def _pdf_via_weasyprint(html: str) -> bytes:
    from weasyprint import HTML

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
