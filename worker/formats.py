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


def markdown_to_html(markdown_text: str) -> str:
    """Convert a Markdown document (LLM answer) to HTML for the viewer and
    as the conversion source for pdf/docx."""
    try:
        import markdown as md_lib
    except ImportError as exc:  # pragma: no cover - exercised via importorskip
        raise RuntimeError(
            "HTML output requires the 'markdown' package (see requirements.txt)"
        ) from exc
    return md_lib.markdown(markdown_text, extensions=["tables", "fenced_code"])


def create_zip_artifact(
    source_dir: Path | None, target: Path, *, fallback_markdown: str
) -> None:
    """Zip a directory tree (e.g. the LLM code-docs kit) into an artifact."""
    import zipfile

    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
        if source_dir is not None:
            for file_path in source_dir.rglob("*"):
                if file_path.is_file():
                    zf.write(file_path, file_path.relative_to(source_dir))
        if not zf.namelist():
            zf.writestr("README.md", fallback_markdown)


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
    import re

    from xhtml2pdf import pisa

    # Large SVG donuts / complex boxes blow up reportlab LayoutError on long audits.
    html = re.sub(r"<svg\b[\s\S]*?</svg>", "", html, flags=re.IGNORECASE)
    html = html.replace("\u2011", "-").replace("\u2013", "-").replace("\u2014", "-")

    font = _ensure_pdf_font()
    path_base = ""
    if font is not None:
        style = (
            "<style>"
            "@font-face{font-family:DocFont;src:url('DocFont.ttf');}"
            "@font-face{font-family:DocFont;src:url('DocFont.ttf');font-weight:bold;}"
            "*{font-family:DocFont,sans-serif;}"
            "svg{display:none}"
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

    def _render(src: str) -> bytes:
        buf = io.BytesIO()
        res = pisa.CreatePDF(src, dest=buf, encoding="utf-8", path=path_base)
        if res.err:
            raise RuntimeError(f"xhtml2pdf failed to render PDF ({res.err} errors)")
        data = buf.getvalue()
        if not data:
            raise RuntimeError("xhtml2pdf produced an empty PDF")
        return data

    try:
        return _render(html)
    except Exception as first:  # noqa: BLE001 — fall back to a flatter document
        # Huge nested cards / flex layouts trip reportlab LayoutError; retry a
        # plain text-ish HTML so PDF remains available on Windows.
        plain = re.sub(r"<style\b[\s\S]*?</style>", "", html, flags=re.IGNORECASE)
        plain = re.sub(r"<script\b[\s\S]*?</script>", "", plain, flags=re.IGNORECASE)
        plain = re.sub(r"<svg\b[\s\S]*?</svg>", "", plain, flags=re.IGNORECASE)
        plain = re.sub(r' class="[^"]*"', "", plain)
        plain = re.sub(r' style="[^"]*"', "", plain)
        # Keep the document bounded for the PDF engine.
        if len(plain) > 180_000:
            plain = plain[:180_000] + "\n</body></html>"
        if font is not None:
            plain = (
                "<html><head><meta charset='utf-8'/>"
                "<style>@font-face{font-family:DocFont;src:url('DocFont.ttf');}"
                "body{font-family:DocFont,sans-serif;font-size:11pt;}</style></head>"
                f"<body>{plain}</body></html>"
            )
        try:
            return _render(plain)
        except Exception as second:  # noqa: BLE001
            raise RuntimeError(
                f"xhtml2pdf failed ({type(first).__name__}: {first}); "
                f"plain retry also failed ({type(second).__name__}: {second})"
            ) from second


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
