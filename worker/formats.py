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


def markdown_without_attached_files(markdown_text: str) -> str:
    """Keep the protocol body; drop inlined «Файл:» dumps (JSON etc.).

    Attachments are already written under ``fstec/attachments/``; embedding
    them into PDF only triggers Courier tofu for Cyrillic inside ``<code>``.
    """
    marker = "\n## Файл:"
    if marker not in markdown_text and not markdown_text.startswith("## Файл:"):
        return markdown_text
    body = markdown_text.split(marker, 1)[0]
    if markdown_text.startswith("## Файл:"):
        body = ""
    note = (
        "\n\n---\n\n"
        "Электронные приложения сохранены отдельными файлами "
        "в каталоге `fstec/attachments/` (и рядом с отчётом).\n"
    )
    return body.rstrip() + note


def markdown_to_html(markdown_text: str) -> str:
    """Convert a Markdown document (LLM answer) to HTML for the viewer and
    as the conversion source for pdf/docx."""
    try:
        import markdown as md_lib
    except ImportError as exc:  # pragma: no cover - exercised via importorskip
        raise RuntimeError(
            "HTML output requires the 'markdown' package (see requirements.txt)"
        ) from exc
    body = md_lib.markdown(markdown_text, extensions=["tables", "fenced_code"])
    # Full document + Unicode-capable stack so viewers and PDF share one base.
    return (
        "<!DOCTYPE html>\n<html lang=\"ru\"><head><meta charset=\"utf-8\"/>"
        "<style>"
        "body{font-family:'Segoe UI','DejaVu Sans',Arial,sans-serif;"
        "font-size:15px;line-height:1.55;color:#111;max-width:960px;"
        "margin:24px auto;padding:0 20px;}"
        "pre,code{font-family:'Segoe UI','DejaVu Sans',Arial,sans-serif;"
        "white-space:pre-wrap;word-break:break-word;}"
        "pre{background:#f4f4f4;padding:12px 14px;border:1px solid #ddd;}"
        "h1,h2,h3{line-height:1.25}"
        "table{border-collapse:collapse;width:100%}"
        "th,td{border:1px solid #bbb;padding:6px 8px;vertical-align:top}"
        "</style></head><body>\n"
        f"{body}\n</body></html>"
    )


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


# xhtml2pdf ignores most CSS variables and mishandles overflow/flex from the
# screen theme — table bodies then vanish while headers and totals remain.
# Default <code>/<pre> map to Courier (no Cyrillic) → black tofu boxes unless
# DocFont is forced on those tags too.
_PDF_BASE_STYLE = """
<style>
  body { background:#fff !important; color:#000 !important; font-size:10pt; }
  .wrap, .card, table, th, td, p, h1, h2, h3, li, .sub, .preview, .foot, .empty,
  .disclaimer, .chip, .mono, code, pre, tt, kbd, samp {
    color:#000 !important; background:#fff !important; box-shadow:none !important;
  }
  .card { border:none; border-bottom:1px solid #bbb; border-radius:0; margin:0 0 12pt;
    padding:8pt 0; }
  table { width:100%; border-collapse:collapse; overflow:visible !important; }
  th, td { border:1px solid #999; padding:4pt 6pt; vertical-align:top; font-size:9pt; }
  th { background:#eee !important; }
  .badge { color:#000 !important; background:#fff !important; border:1px solid #000;
    border-radius:3pt; padding:1pt 4pt; font-size:8pt; }
  .chip { border:1px solid #000; border-radius:3pt; padding:2pt 6pt; }
  .disclaimer { border:1px dashed #555; padding:6pt 8pt; }
  .chips { margin:6pt 0; }
  pre { border:1px solid #ccc; padding:6pt; white-space:pre-wrap; }
  code, pre, tt, kbd, samp, .mono { white-space:pre-wrap; word-wrap:break-word; }
  svg { display:none !important; }
</style>
"""


def _prepare_html_for_pdf(html: str) -> str:
    """Flatten screen-theme HTML into something xhtml2pdf can paginate."""
    import re

    html = re.sub(r"<svg\b[\s\S]*?</svg>", "", html, flags=re.IGNORECASE)
    html = html.replace("\u2011", "-").replace("\u2013", "-").replace("\u2014", "-")
    # Drop overflow clipping that swallows multi-page table bodies.
    html = re.sub(r"overflow\s*:\s*hidden\s*;?", "overflow:visible;", html, flags=re.IGNORECASE)
    # Drop inline badge colors — white text on pastel fills vanishes in PDF.
    html = re.sub(
        r'(\s)style="background:\s*#[0-9A-Fa-f]{3,8};"',
        "",
        html,
    )
    # Kill monospace stacks (Courier/Consolas) that lack Cyrillic in PDF fonts.
    html = re.sub(
        r"font-family\s*:\s*[^;]+;",
        "font-family:DocFont,sans-serif;",
        html,
        flags=re.IGNORECASE,
    )
    return html


def _inject_head_style(html: str, style: str) -> str:
    lower = html.lower()
    if "<head" in lower:
        idx = lower.index("<head")
        gt = html.index(">", idx) + 1
        return html[:gt] + style + html[gt:]
    return f"<html><head>{style}</head><body>{html}</body></html>"


def _pdf_via_xhtml2pdf(html: str) -> bytes:
    import re

    from xhtml2pdf import pisa

    html = _prepare_html_for_pdf(html)
    font = _ensure_pdf_font()
    path_base = ""
    style = _PDF_BASE_STYLE
    if font is not None:
        style = (
            "<style>"
            "@font-face{font-family:DocFont;src:url('DocFont.ttf');}"
            "@font-face{font-family:DocFont;src:url('DocFont.ttf');font-weight:bold;}"
            "*,pre,code,tt,kbd,samp,.mono{"
            "font-family:DocFont,sans-serif !important;}"
            "</style>"
        ) + style
        path_base = str(font.parent) + "/"
    html = _inject_head_style(html, style)

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
