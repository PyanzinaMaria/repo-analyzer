"""Glue between language handlers and the shared static-analysis engine (app/sast/engine.py)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.core.config import get_settings, load_yaml_settings
from app.models.finding import Finding
from app.sast.engine import LanguageRun, analyze_language, merged_to_finding, tools_for


def configured_tools(language: str) -> list[str]:
    cfg = load_yaml_settings(get_settings().settings_path)
    return tools_for(language, (cfg.get("sast") or {}).get("tools"))


def run_static_stage(
    root: Path,
    language: str,
    job_ctx: dict[str, Any] | None,
) -> tuple[list[Finding], LanguageRun]:
    """SAST (+ optional context) for one language.

    Outputs under job_ctx['work_dir']/<language> when the orchestrator provides it
    (kept next to the scan's reports, not as UI artifacts), else in a temp dir.
    Context builds when job_ctx['build_context'] is true (default True for static).
    """
    ctx = job_ctx or {}
    work = ctx.get("work_dir")
    build_context = bool(ctx.get("build_context", True))
    run = analyze_language(
        root,
        language,
        Path(work) / language if work else None,
        configured_tools(language),
        build_context=build_context,
    )
    return [merged_to_finding(m, language) for m in run.merged], run
