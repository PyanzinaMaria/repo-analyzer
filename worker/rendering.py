"""Artifact rendering: turns a ScanResult into the frontend contract files.

Produces self-contained Russian HTML (inline CSS, inline SVG — no external
resources, so the artifacts are safe inside the frontend's sandboxed iframes
with ``Content-Security-Policy: sandbox allow-scripts``).
"""

from __future__ import annotations

import html
import math
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

# Analyzer severities the frontend theme does not know about, and the key
# they are folded into (frontend/config/theme.yaml defines critical..info).
UNKNOWN_SEVERITY_ALIASES = {"unknown"}
UNKNOWN_SEVERITY_TARGET = "info"

# Highest first: findings cards and the FSTEC protocol table use this order.
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Inventory lists are truncated in doc.html; they can hold thousands of names.
INVENTORY_PREVIEW_LIMIT = 50

# autoescape is forced on (not select_autoescape) because template filenames
# end in .j2, which the extension-based selector does not recognize as HTML.
_ENV = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=True,
)


def severity_counts(result) -> dict[str, int]:
    """result.summary['by_severity'] mapped to the frontend's severity keys."""
    by_severity = (result.summary or {}).get("by_severity") or {}
    counts: dict[str, int] = {}
    for severity, count in by_severity.items():
        key = UNKNOWN_SEVERITY_TARGET if severity in UNKNOWN_SEVERITY_ALIASES else severity
        counts[key] = counts.get(key, 0) + int(count)
    return {k: v for k, v in counts.items() if v > 0}


def ordered_findings(result) -> list:
    return sorted(
        result.findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity.value, SEVERITY_ORDER["info"]), f.file or "", f.line or 0),
    )


def svg_donut(counts: dict[str, int], colors: dict[str, str], size: int = 220) -> str:
    """Inline SVG donut of severity proportions; empty when there is nothing
    to draw (the scan page hides the results block in that case anyway)."""
    total = sum(counts.values())
    if total <= 0:
        return ""
    radius = size / 2 - 14
    circumference = 2 * math.pi * radius
    segments: list[str] = []
    offset = 0.0
    for severity, count in counts.items():
        fraction = count / total
        dash = fraction * circumference
        color = colors.get(severity, colors.get(UNKNOWN_SEVERITY_TARGET, "#8A5A73"))
        segments.append(
            f'<circle cx="{size / 2}" cy="{size / 2}" r="{radius}" fill="none" '
            f'stroke="{html.escape(color)}" stroke-width="26" '
            f'stroke-dasharray="{dash:.2f} {circumference - dash:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 {size / 2} {size / 2})" />'
        )
        offset += dash
    center = (
        f'<text x="{size / 2}" y="{size / 2 - 4}" text-anchor="middle" class="donut-num">{total}</text>'
        f'<text x="{size / 2}" y="{size / 2 + 18}" text-anchor="middle" class="donut-label">находок</text>'
    )
    return f'<svg viewBox="0 0 {size} {size}" role="img" class="donut">{"".join(segments)}{center}</svg>'


def _inventory_rows(result) -> list[dict]:
    rows = []
    for inv in result.inventories:
        rows.append(
            {
                "language": inv.language,
                "files_count": inv.files_count,
                "modules": inv.modules,
                "classes": inv.classes,
                "functions": inv.functions,
                "modules_preview": inv.modules[:INVENTORY_PREVIEW_LIMIT],
                "classes_preview": inv.classes[:INVENTORY_PREVIEW_LIMIT],
                "functions_preview": inv.functions[:INVENTORY_PREVIEW_LIMIT],
                "hidden_modules": max(0, len(inv.modules) - INVENTORY_PREVIEW_LIMIT),
                "hidden_classes": max(0, len(inv.classes) - INVENTORY_PREVIEW_LIMIT),
                "hidden_functions": max(0, len(inv.functions) - INVENTORY_PREVIEW_LIMIT),
                "dependency_files": inv.dependency_files,
            }
        )
    return rows


def _finding_rows(result) -> list[dict]:
    rows = []
    for position, finding in enumerate(ordered_findings(result), start=1):
        rows.append(
            {
                "position": position,
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity.value,
                "cwe": finding.cwe,
                "file": finding.file,
                "line": finding.line,
                "rule_id": finding.rule_id,
                "source": finding.source,
                "remediation": finding.remediation,
            }
        )
    return rows


def _meta_lines(result) -> list[str]:
    meta = result.meta or {}
    lines: list[str] = []
    languages = meta.get("languages") or {}
    for lang, info in sorted(languages.items()):
        if info.get("skipped"):
            lines.append(f"{lang}: анализ пропущен ({info.get('reason', 'нет данных')})")
    ai = meta.get("ai") or {}
    if ai.get("enabled"):
        status = ai.get("status", "unknown")
        text = f"ИИ-анализ: {status}"
        if ai.get("model"):
            text += f", модель {ai['model']}"
        if ai.get("error"):
            text += f" ({ai['error']})"
        lines.append(text)
    return lines


def _fmt_ts(value: datetime) -> str:
    return value.strftime("%d.%m.%Y %H:%M UTC")


def render_report(result, cfg) -> str:
    """report.html — audit report for the «Отчёт аудита» viewer page."""
    counts = severity_counts(result)
    template = _ENV.get_template("report.html.j2")
    return template.render(
        project_name=result.project_name,
        scan_id=result.scan_id,
        generated_at=_fmt_ts(result.generated_at),
        counts=counts,
        total=sum(counts.values()),
        donut=svg_donut(counts, cfg.severity_colors),
        severity_colors=cfg.severity_colors,
        summary=result.summary or {},
        findings=_finding_rows(result),
        meta_lines=_meta_lines(result),
        colors=cfg.colors,
    )


def render_doc(result, cfg) -> str:
    """doc.html — ФСТЭК-style documentation draft for the «Документация» viewer."""
    counts = severity_counts(result)
    template = _ENV.get_template("doc.html.j2")
    return template.render(
        project_name=result.project_name,
        scan_id=result.scan_id,
        generated_at=_fmt_ts(result.generated_at),
        enabled_languages=result.enabled_languages,
        counts=counts,
        total=sum(counts.values()),
        inventories=_inventory_rows(result),
        findings=_finding_rows(result),
        severity_colors=cfg.severity_colors,
        disclaimer=cfg.doc_disclaimer,
        colors=cfg.colors,
    )
