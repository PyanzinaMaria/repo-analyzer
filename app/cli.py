"""Product CLI: `python -m app <command>`.

  scan PATH|URL   analyze a local directory, a .zip archive or a GitHub link with the same pipeline as the
                  worker/API (SAST + code context + optional LLM triage/discovery), print the audit and write
                  the reports (security_report.md/json, fstec_draft.md, audit_report.md)
  serve           run the analyzer HTTP API (FastAPI, Swagger at /docs)
  env             analyzer and tool versions
  llmflow ...     LLM-integrated code: untrusted input -> prompt -> LLM -> dangerous sink (docs/llmflow/)
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Optional

import typer

cli = typer.Typer(no_args_is_help=True, add_completion=False, help=__doc__)


def _mount_subcommands() -> None:
    from app.llmflow.cli import app as llmflow_app

    cli.add_typer(llmflow_app, name="llmflow")


_mount_subcommands()


@cli.command("scan")
def scan(
    target: str = typer.Argument(..., help="Local directory, .zip archive or https://github.com/<org>/<repo>"),
    name: Optional[str] = typer.Option(None, help="Project name in the reports"),
    ai: Optional[bool] = typer.Option(None, "--ai/--no-ai",
                                      help="Force the LLM stage on/off (default: config/settings.yaml ai.enabled)"),
    modes: Optional[str] = typer.Option(None, help="LLM modes, e.g. triage,discovery (or review)"),
    tools: Optional[str] = typer.Option(None, help="SAST tools, e.g. bandit,semgrep (default: settings.yaml)"),
    out: Optional[Path] = typer.Option(None, help="Copy the reports into this directory"),
    md: Optional[Path] = typer.Option(None, help="Also write the audit document (Markdown) here"),
    svg: Optional[Path] = typer.Option(None, help="Also save the terminal audit as SVG"),
    json_out: Optional[Path] = typer.Option(None, "--json", help="Also write the full scan result (JSON) here"),
    top: int = typer.Option(10, help="Findings in the table"),
    details: int = typer.Option(3, help="Findings shown with explanation and code"),
    width: int = typer.Option(120, help="Width for SVG export"),
):
    """Scan a repository and print its security audit."""
    if modes:
        os.environ["AI_MODES"] = modes
    if tools is not None:
        os.environ["SECAUDIT_SAST_TOOLS"] = tools

    from rich.console import Console

    from app.core.config import get_settings
    from app.core.logging import setup_logging
    from app.services.ingest import IngestService
    from app.services.report.audit import render, render_markdown, render_to_svg
    from app.services.scan import ScanOrchestrator
    from app.services.scan.ranking import audit_from_scan
    from app.services.store import ProjectStore

    setup_logging()
    get_settings.cache_clear()
    console = Console()
    store = ProjectStore()
    ingest = IngestService(store=store)
    with console.status("ingest…"):
        if target.startswith(("http://", "https://")):
            project = ingest.create_from_github(target, name=name)
        elif target.lower().endswith(".zip"):
            project = ingest.create_from_zip_bytes(Path(target).read_bytes(), Path(target).name, name=name)
        else:
            project = ingest.create_from_local_path(target, name=name or Path(target).resolve().name)
    with console.status("analysis (SAST, code context, LLM)…"):
        scan_info = ScanOrchestrator(store=store).start_scan(project.id, enable_ai=ai)
    result = store.get_result(project.id, scan_info.id)
    reports = store.reports_dir(project.id, scan_info.id)
    repo_url = project.source_ref if project.source_type.value == "github" else None
    data = audit_from_scan(result, Path(project.workspace_path), reports / "secaudit", repo_url)
    render(data, console, top=top, details=details)

    llm = (result.meta or {}).get("llm") or {}
    if llm.get("status") not in (None, "skipped"):
        console.print(f"LLM: {llm.get('model')} · {llm.get('status')} · {llm.get('answers')}"
                      + (f" · {llm['error']}" if llm.get("error") else ""))
    elif llm.get("error"):
        console.print(f"[dim]LLM stage skipped: {llm['error']}[/dim]")
    if md:
        md.parent.mkdir(parents=True, exist_ok=True)
        md.write_text(render_markdown(data, top=top, details=max(details, 5)), encoding="utf-8")
    if svg:
        render_to_svg(data, svg, width=width, top=top, details=details)
    if json_out:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    if out:
        out.mkdir(parents=True, exist_ok=True)
        for f in ("security_report.md", "security_report.json", "fstec_draft.md", "audit_report.md"):
            if (reports / f).exists():
                shutil.copy2(reports / f, out / f)
    console.print(f"reports: {out or reports}")


@cli.command("serve")
def serve(host: Optional[str] = typer.Option(None), port: Optional[int] = typer.Option(None)):
    """Run the analyzer HTTP API (uvicorn)."""
    import uvicorn

    from app.core.config import get_settings

    s = get_settings()
    uvicorn.run("app.main:app", host=host or s.app_host, port=port or s.app_port, reload=False)


@cli.command("env")
def env():
    """Analyzer and tool versions (Semgrep, Bandit, Node/ESLint, CodeQL)."""
    from rich.console import Console

    from app.core.runlog import record_env
    from app.core.yaml_configs import load_sast_config
    from app.sast import tools as toolmod

    toolmod.set_overrides(load_sast_config().tool_paths)
    Console().print_json(data=record_env())
