"""`python -m app llmflow ...`: LLM-integrated code flows (untrusted input -> prompt -> LLM -> dangerous sink).

  scan PATH     inventory of LLM call sites, ranked flows (S*E*R), hygiene; writes JSON, optional SVG/Mermaid
  rules         write the generated Semgrep rules (pass 0) to a directory
  test-rules    `semgrep --test` over every catalog entry's snippets (config/llmflow/tests)
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

app = typer.Typer(no_args_is_help=True, add_completion=False, help=__doc__)


def _console(width: Optional[int] = None):
    import sys

    from rich.console import Console

    # Windows consoles default to a legacy code page; the views use emoji and box drawing
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except (OSError, ValueError):
            pass
    return Console(width=width)


@app.command("scan")
def scan(
    path: Path = typer.Argument(..., exists=True, file_okay=False, help="Local repository directory"),
    out: Optional[Path] = typer.Option(None, help="Output directory (default: data/llmflow/<repo>)"),
    top: int = typer.Option(15, help="Flows in the table"),
    details: int = typer.Option(3, help="Flows drawn as full taint paths"),
    max_depth: int = typer.Option(3, help="Stitching passes over wrapper functions"),
    frameworks: bool = typer.Option(False, help="Also LangChain / LlamaIndex / litellm sources"),
    sinks: Optional[str] = typer.Option(None, help="Extra sink classes to enable, e.g. text"),
    include_tests: bool = typer.Option(False, help="Also analyze tests/ and test_*.py"),
    exclude: list[str] = typer.Option([], help="Extra paths/globs to skip (repeatable)"),
    json_out: Optional[Path] = typer.Option(None, "--json", help="Also copy findings.json here"),
    svg: Optional[Path] = typer.Option(None, help="Save the terminal report as SVG"),
    mermaid: Optional[Path] = typer.Option(None, help="Write Mermaid graphs (attack surface + top flows) as .md"),
    mermaid_top: int = typer.Option(5, help="Flows drawn in the Mermaid file"),
    width: int = typer.Option(140, help="Width for SVG export"),
    no_hygiene: bool = typer.Option(False, help="Hide the hygiene table"),
):
    """Find and rank flows from untrusted input through an LLM into dangerous sinks."""
    import shutil

    from app.core.yaml_configs import REPO_ROOT
    from app.llmflow.pipeline import Options, run
    from app.llmflow.semgrep import SemgrepFailed, SemgrepMissing
    from app.llmflow.viz import mermaid_markdown, render, render_to_svg

    console = _console()
    root = path.resolve()
    out_dir = (out or REPO_ROOT / "data" / "llmflow" / root.name).resolve()
    opts = Options(max_depth=max_depth, frameworks=frameworks, include_tests=include_tests, excludes=list(exclude),
                   extra_sinks={s.strip() for s in (sinks or "").split(",") if s.strip()})
    try:
        with console.status("llmflow…") as status:
            res = run(root, out_dir, opts, progress=lambda m: status.update(f"llmflow · {m}"))
    except (SemgrepMissing, SemgrepFailed) as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(2) from None
    render(res, console, top=top, details=details, hygiene=not no_hygiene)
    if svg:
        render_to_svg(res, svg, width=width, top=top, details=details, hygiene=not no_hygiene)
        console.print(f"[dim]svg: {svg}[/]")
    if mermaid:
        mermaid.parent.mkdir(parents=True, exist_ok=True)
        mermaid.write_text(mermaid_markdown(res, top=mermaid_top), encoding="utf-8")
        console.print(f"[dim]mermaid: {mermaid}[/]")
    if json_out:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(out_dir / "findings.json", json_out)
    console.print(f"[dim]outputs: {out_dir}  (inventory.json, findings.json, hygiene.json, summary.json, rules/)[/]")


bench_app = typer.Typer(no_args_is_help=True, add_completion=False,
                        help="Real-vulnerability benchmark (config/llmflow/bench/*.yaml), e.g. TaintP2X's 35 CVEs.")
app.add_typer(bench_app, name="bench")


def _bench_entries(manifest: str, only: Optional[str]):
    from app.llmflow.bench import load_manifest

    entries = load_manifest(manifest).entries
    if only:
        wanted = {s.strip() for s in only.split(",")}
        entries = [e for e in entries if e.id in wanted or e.cve in wanted]
    return entries


@bench_app.command("fetch")
def bench_fetch(manifest: str = typer.Option("taintp2x35", help="Manifest name or path"),
                only: Optional[str] = typer.Option(None, help="Comma-separated entry ids / CVEs")):
    """Shallow-clone every (repo, ref) of the manifest into data/llmflow/bench/repos/."""
    from app.llmflow.bench import fetch

    console = _console()
    done: dict = {}
    for e in _bench_entries(manifest, only):
        key = (e.repo, e.ref)
        if key not in done:
            done[key] = fetch(e)
        status = done[key]
        console.print(f"{e.id} {e.repo}@{e.ref}: " + (f"[green]{status}[/]" if status in ("ok", "cached")
                                                     else f"[red]{status}[/]"))


@bench_app.command("check")
def bench_check(manifest: str = typer.Option("taintp2x35", help="Manifest name or path"),
                only: Optional[str] = typer.Option(None, help="Comma-separated entry ids / CVEs")):
    """Verify that each entry's expected file exists in its checkout."""
    from app.llmflow.bench import check

    console = _console()
    bad = 0
    for e in _bench_entries(manifest, only):
        files = check(e)
        bad += not files
        console.print(f"{e.id} {e.cve}: " + (f"[green]{len(files)} file(s)[/] {', '.join(files[:3])}" if files
                                            else f"[red]no file matches {e.expect.file} under {e.target}[/]"))
    raise typer.Exit(1 if bad else 0)


@bench_app.command("run")
def bench_run(manifest: str = typer.Option("taintp2x35", help="Manifest name or path"),
              only: Optional[str] = typer.Option(None, help="Comma-separated entry ids / CVEs"),
              rescan: bool = typer.Option(False, help="Ignore cached scans"),
              frameworks: bool = typer.Option(False, help="Also LangChain / LlamaIndex / litellm sources"),
              out: Optional[Path] = typer.Option(None, help="Where results.json goes "
                                                            "(default: data/llmflow/bench/<sdk|fw>)"),
              md: Optional[Path] = typer.Option(None, help="Also write the comparison table as Markdown")):
    """Scan every checkout, match findings to the known vulnerabilities, compare with published results."""
    from app.llmflow.bench import BENCH_DIR, run_bench, write_results
    from app.llmflow.pipeline import Options
    from app.llmflow.viz import bench_markdown, bench_table

    console = _console()
    entries = _bench_entries(manifest, only)
    out = out or BENCH_DIR / ("fw" if frameworks else "sdk")
    with console.status("bench…") as status:
        results = run_bench(entries, Options(frameworks=frameworks),
                            progress=lambda m: status.update(f"bench · {m}"), rescan=rescan)
    summ = write_results(results, out)
    console.print(bench_table(results, summ))
    if md:
        md.parent.mkdir(parents=True, exist_ok=True)
        md.write_text(bench_markdown(results, summ), encoding="utf-8")
        console.print(f"[dim]markdown: {md}[/]")
    console.print(f"[dim]results: {out / 'results.json'}[/]")


@app.command("rules")
def rules(out: Path = typer.Option(Path("data/llmflow/rules"), help="Directory for the generated rules"),
          sinks: Optional[str] = typer.Option(None, help="Extra sink classes to enable, e.g. text")):
    """Write the generated pass-0 Semgrep rules (call sites, taint, gates, sources, hygiene)."""
    from collections import Counter

    from app.llmflow.catalog import load_catalog
    from app.llmflow.rulegen import static_rules, write_rules

    console = _console()
    rs = static_rules(load_catalog(), {s.strip() for s in (sinks or "").split(",") if s.strip()})
    p = write_rules(rs, out / "llmflow.yaml")
    fams = Counter(r.get("metadata", {}).get("family", "?") for r in rs)
    console.print(f"{len(rs)} rules → {p}")
    console.print("  " + "  ".join(f"{k}: {v}" for k, v in sorted(fams.items())))


@app.command("test-rules")
def test_rules(keep: Optional[Path] = typer.Option(None, help="Keep the generated test directory here"),
               verbose: bool = typer.Option(False, "-v", help="Print semgrep output")):
    """Run `semgrep --test` over the generated rules and config/llmflow/tests/*.py."""
    from app.llmflow.ruletest import run_rule_tests
    from app.llmflow.semgrep import SemgrepMissing

    console = _console()
    try:
        ok, out, names = run_rule_tests(keep)
    except SemgrepMissing as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(2) from None
    for line in out.splitlines():
        if line.startswith("== "):
            console.print(("[green]✔[/] " if line.endswith("ok") else "[red]✖[/] ") + line[3:])
        elif verbose or not ok:
            console.print(line, markup=False, highlight=False)
    console.print(f"[bold {'green' if ok else 'red'}]{'all rule tests passed' if ok else 'rule tests failed'}[/]"
                  f" ({len(names)} snippet files)")
    raise typer.Exit(0 if ok else 1)
