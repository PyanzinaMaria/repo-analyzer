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
        color = colors.get(severity, colors.get(UNKNOWN_SEVERITY_TARGET, "#A49FD1"))
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


def _finding_method(source: str | None) -> str:
    """Map analyzer finding.source to a report section id."""
    src = (source or "").lower()
    if src == "ai" or src.startswith("ai-") or src.startswith("ai+"):
        return "llm"
    if src.startswith("dast") or src in {"zap-baseline", "zap"}:
        return "dast"
    if src in {"pentest", "llm-review", "review-agent"} or src.startswith("pentest"):
        return "pentest"
    return "sast"


# Long ZAP/LLM texts collapse in the HTML report; keep a short preview open.
_DESC_COLLAPSE_CHARS = 280


def _plain_text(value: str | None) -> str:
    """Strip markup so ZAP HTML blobs do not show raw <p>/<ul> in the report."""
    import html as html_lib
    import re

    text = str(value or "")
    text = re.sub(r"(?is)<script[^>]*>.*?</script>", " ", text)
    text = re.sub(r"(?is)<style[^>]*>.*?</style>", " ", text)
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = re.sub(r"(?i)</p\s*>", "\n\n", text)
    text = re.sub(r"(?i)</li\s*>", "\n", text)
    text = re.sub(r"(?i)<li[^>]*>", "• ", text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = html_lib.unescape(text)
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r"[ \t]{2,}", " ", text)
    return text.strip()


def _finding_row(finding, position: int) -> dict:
    extra = finding.extra or {}
    dismissed = bool(extra.get("dismissed"))
    description = _plain_text(finding.description)
    preview = description
    collapse = len(description) > _DESC_COLLAPSE_CHARS
    if collapse:
        cut = description[:_DESC_COLLAPSE_CHARS].rsplit(" ", 1)[0]
        preview = (cut or description[:_DESC_COLLAPSE_CHARS]).rstrip(".,;:") + "…"
    triage = extra.get("triage")
    if isinstance(triage, dict) and triage.get("explanation"):
        triage = {**triage, "explanation": _plain_text(triage.get("explanation"))}
    return {
        "position": position,
        "title": finding.title,
        "description": description,
        "description_preview": preview,
        "description_collapse": collapse,
        "severity": finding.severity.value,
        "cwe": finding.cwe,
        "file": finding.file,
        "line": finding.line,
        "rule_id": finding.rule_id,
        "source": finding.source,
        "remediation": _plain_text(finding.remediation) if finding.remediation else finding.remediation,
        "url": extra.get("url"),
        "evidence": extra.get("evidence"),
        "method": _finding_method(finding.source),
        "dismissed": dismissed,
        "verdict": extra.get("verdict"),
        "triage": triage,
        "dataflow": extra.get("dataflow"),
        "tools": extra.get("tools"),
        "snippet": extra.get("snippet"),
    }


def _finding_rows(result) -> list[dict]:
    return [
        _finding_row(finding, position)
        for position, finding in enumerate(ordered_findings(result), start=1)
    ]


SECTION_LABELS = {
    "sast": "SAST — статический анализ",
    "llm": "LLM-агент",
    "dast": "DAST — динамический анализ",
    "pentest": "Пентест",
}

# Runner keys from orchestrator meta.runners → section ids.
_RUNNER_TO_SECTION = {
    "static": "sast",
    "ai": "llm",
    "dynamic": "dast",
    "manual": "pentest",
}


def _active_sections(result) -> list[str]:
    """Ordered section ids that should appear in the unified audit report."""
    meta = result.meta or {}
    summary = result.summary or {}
    runners = meta.get("runners")
    if runners:
        sections = []
        for runner in runners:
            section = _RUNNER_TO_SECTION.get(runner)
            if section and section not in sections:
                sections.append(section)
        return sections

    # Legacy jobs without an explicit runner list: infer from result.
    sections: list[str] = ["sast"]
    ai = meta.get("ai") or {}
    if ai.get("enabled") or any(_finding_method(f.source) == "llm" for f in result.findings):
        sections.append("llm")
    kind = str(summary.get("scan_kind") or "")
    dast_meta = meta.get("dast") or {}
    zap = dast_meta.get("zap") if isinstance(dast_meta.get("zap"), dict) else {}
    zap_ran = bool(zap) and zap.get("status") not in {None, "skipped"}
    has_dast_findings = any(_finding_method(f.source) == "dast" for f in result.findings)
    if has_dast_findings or zap_ran or kind in {"dast", "sast+dast"}:
        sections.append("dast")
    has_pentest_findings = any(_finding_method(f.source) == "pentest" for f in result.findings)
    security_status = (meta.get("security") or {}).get("status")
    if (
        "pentest" in kind
        or has_pentest_findings
        or security_status not in {None, "disabled", "skipped"}
    ):
        sections.append("pentest")
    return sections


def _method_sections(result) -> list[dict]:
    """Findings grouped under SAST / LLM / DAST / Пентест for the unified report."""
    rows = [r for r in _finding_rows(result) if not r.get("dismissed")]
    by_method: dict[str, list[dict]] = {key: [] for key in SECTION_LABELS}
    for row in rows:
        by_method.setdefault(row["method"], []).append(row)

    meta = result.meta or {}
    dast_meta = meta.get("dast") or {}
    attack = meta.get("attack_surface") or {}
    ranking = meta.get("ranking")
    sections = []
    for section_id in _active_sections(result):
        entry = {
            "id": section_id,
            "label": SECTION_LABELS[section_id],
            "findings": by_method.get(section_id, []),
            "dast": dast_meta if section_id == "dast" else None,
            "pentest": (dast_meta.get("pentest") if isinstance(dast_meta, dict) else None)
            if section_id == "pentest"
            else None,
            "security": meta.get("security") if section_id == "pentest" else None,
            "attack_surface": attack if section_id == "sast" and attack else None,
            "ranking": ranking if section_id in {"sast", "llm"} else None,
            "llm_meta": (meta.get("llm") or meta.get("ai") or {}) if section_id == "llm" else None,
        }
        sections.append(entry)
    return sections


def _meta_lines(result) -> list[str]:
    meta = result.meta or {}
    lines: list[str] = []
    sections = _active_sections(result)
    if sections:
        labels = [SECTION_LABELS[s] for s in sections]
        lines.append("Методы: " + "; ".join(labels))
    languages = meta.get("languages") or {}
    for lang, info in sorted(languages.items()):
        if info.get("skipped"):
            lines.append(f"{lang}: анализ пропущен ({info.get('reason', 'нет данных')})")
    ai = meta.get("ai") or {}
    if ai.get("enabled") or "llm" in sections:
        status = ai.get("status", "unknown")
        text = f"ИИ-анализ: {status}"
        if ai.get("model"):
            text += f", модель {ai['model']}"
        if ai.get("error"):
            text += f" ({ai['error']})"
        lines.append(text)
    dast = meta.get("dast") or {}
    runners = meta.get("runners") or []
    show_dast = "dast" in sections or "dynamic" in runners
    if show_dast and dast:
        status = dast.get("status", "unknown")
        text = f"DAST: {status}"
        if dast.get("target_url"):
            text += f", цель {dast['target_url']}"
        lines.append(text)
    if "pentest" in sections:
        pentest = dast.get("pentest") if isinstance(dast, dict) else None
        security = meta.get("security") or {}
        if isinstance(pentest, dict) and pentest.get("status"):
            text = f"Пентест: {pentest.get('status')}"
            if pentest.get("mode"):
                text += f", режим {pentest.get('mode')}"
            lines.append(text)
        elif security.get("status") and security.get("status") != "disabled":
            lines.append(f"Пентест (ревью): {security.get('status')}")
        target = dast.get("target_url") if isinstance(dast, dict) else None
        if target and not show_dast:
            lines.append(f"Цель проверки: {target}")
    return lines


def _fmt_ts(value: datetime) -> str:
    return value.strftime("%d.%m.%Y %H:%M UTC")


def render_report(result, cfg) -> str:
    """report.html — unified audit report with method sections."""
    counts = severity_counts(result)
    sections = _method_sections(result)
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
        sections=sections,
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
