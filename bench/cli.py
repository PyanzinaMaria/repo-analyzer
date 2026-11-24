"""Research CLI: `python -m bench <stage> <cmd>` (benchmark, SAST, context, LLM, evaluation, audit). Every command
is idempotent unless --force."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from app.core.yaml_configs import CONFIG_DIR, load_sast_config

from bench.config import Paths
from app.core.runlog import RunSummary, console, record_env, setup_logging

cli = typer.Typer(no_args_is_help=True, add_completion=False, help=__doc__)
bench_app = typer.Typer(no_args_is_help=True, help="Stage A: benchmark construction")
sast_app = typer.Typer(no_args_is_help=True, help="Stage B: SAST runs")
context_app = typer.Typer(no_args_is_help=True, help="Stage C: code context")
llm_app = typer.Typer(no_args_is_help=True, help="Stage D: LLM triage/discovery")
eval_app = typer.Typer(no_args_is_help=True, help="Stage E: evaluation")
audit_app = typer.Typer(no_args_is_help=True, help="Per-repository audit report (terminal / SVG / Markdown)")
for name, sub in [("bench", bench_app), ("sast", sast_app), ("context", context_app),
                  ("llm", llm_app), ("eval", eval_app), ("audit", audit_app)]:
    cli.add_typer(sub, name=name)


@cli.callback()
def _main(verbose: bool = typer.Option(False, "--verbose", "-v")):
    setup_logging(verbose)


@cli.command("env")
def env_cmd():
    """Record analyzer/tool versions to results/env.json."""
    env = record_env(Paths().results / "env.json")
    console.print_json(data=env)


# ----------------------------------------------------------------------------- Stage A


@bench_app.command("build")
def bench_build(
    config: Path = typer.Option(CONFIG_DIR / "benchmark.yaml", "--config"),
    limit: Optional[int] = typer.Option(None, help="Stop after this many accepted main items (smoke runs)"),
    force: bool = typer.Option(False, help="Re-download sources and recompute candidates"),
):
    """Collect sources, extract ground truth, filter, sample and split -> benchmark.jsonl."""
    from bench.build import build

    with RunSummary("bench build") as s:
        build(config, limit=limit, force=force, summary=s)


@bench_app.command("checkout")
def bench_checkout(
    split: Optional[str] = typer.Option(None, help="dev|test|post_cutoff|extra; default all"),
    limit: Optional[int] = typer.Option(None),
    force: bool = typer.Option(False),
):
    """Create vuln/fixed worktrees for benchmark items."""
    from bench.build import checkout_all

    with RunSummary("bench checkout") as s:
        checkout_all(split=split, limit=limit, force=force, summary=s)


@bench_app.command("external")
def bench_external(
    action: str = typer.Argument("build", help="build|scan"),
    kind: str = typer.Argument(..., help="owasp-java|owasp-python|seclens|realvuln"),
    tools: Optional[str] = typer.Option(None, help="scan: comma-separated subset of tools"),
    sast_config: Path = typer.Option(CONFIG_DIR / "sast.yaml", "--sast-config"),
    config: Path = typer.Option(CONFIG_DIR / "external.yaml", "--config"),
    force: bool = typer.Option(False),
):
    """Build an external benchmark corpus or scan its snapshot groups (findings are
    attributed to every item sharing the same repo+commit)."""
    from bench import external

    cfgx = external.load_config(config)
    with RunSummary(f"external {action} {kind}") as s:
        if action == "build":
            s.inc("items", len(external.build(kind, cfgx, force=force)))
        elif action == "scan":
            external.scan(kind, cfgx, [t.strip() for t in tools.split(",") if t.strip()] if tools else None,
                          sast_config, force=force, summary=s)
        else:
            raise typer.BadParameter("action must be build or scan")


@bench_app.command("compare")
def bench_compare(
    dirs: list[Path] = typer.Argument(None, help="Corpus data dirs containing results/metrics.json"),
    out: Path = typer.Option(Path("docs") / "BENCHMARK-COMPARISON.md", "--out"),
):
    """Render cross-corpus metric comparison into one markdown file."""
    from bench.compare import compare

    with RunSummary("bench compare") as s:
        path = compare([d for d in dirs if d], out, summary=s)
        s.notes.append(f"wrote {path}")


@bench_app.command("stats")
def bench_stats(out: Optional[Path] = typer.Option(None, help="Also write the stats to this file (e.g. docs/BENCHMARK.md)")):
    """Write results/benchmark_stats.md (counts, LOC, ground truth, linked item list)."""
    from bench.stats import write_stats

    path = write_stats(extra_out=out)
    console.print(f"wrote {path}" + (f" and {out}" if out else ""))


@bench_app.command("manual-sample")
def bench_manual_sample(
    fraction: float = typer.Option(0.2), seed: int = typer.Option(13), force: bool = typer.Option(False)
):
    """Pick a random sample of test items and write results/manual_check.md for human review."""
    from bench.manual import write_manual_sample

    path = write_manual_sample(fraction=fraction, seed=seed, force=force)
    console.print(f"wrote {path}")


@bench_app.command("mark-checked")
def bench_mark_checked(
    item_id: str,
    ok: bool = typer.Option(..., "--ok/--bad", help="Do gt_locations point at the vulnerability?"),
    note: str = typer.Option("", help="Free-text note"),
):
    """Record a human verdict on an item's ground truth."""
    from bench.manual import mark_checked

    mark_checked(item_id, ok, note)
    console.print(f"{item_id}: manually_checked=True label_ok={ok}")


# ----------------------------------------------------------------------------- Stage B


@sast_app.command("run")
def sast_run(
    tools: Optional[str] = typer.Option(None, help="Comma-separated subset of tools"),
    split: Optional[str] = typer.Option(None, help="Benchmark split to run on"),
    path: Optional[Path] = typer.Option(None, help="Ad-hoc directory instead of benchmark items"),
    language: Optional[str] = typer.Option(None, help="Language for --path (auto-detected)"),
    out: Optional[Path] = typer.Option(None, help="Output dir for --path"),
    limit: Optional[int] = typer.Option(None),
    force: bool = typer.Option(False),
    config: Path = typer.Option(CONFIG_DIR / "sast.yaml", "--config"),
):
    """Run SAST tools; write SARIF, findings.jsonl and merged.jsonl."""
    from app.sast import tools as toolmod
    from app.sast.run import detect_language, run_tools, run_tools_isolated

    cfg = load_sast_config(config)
    toolmod.set_overrides(cfg.tool_paths)
    tool_list = ([t.strip() for t in tools.split(",") if t.strip()] if tools is not None
                 else [name for name, spec in cfg.tools.items() if spec.enabled])
    if unknown := set(tool_list).difference(cfg.tools):
        raise typer.BadParameter(f"Unknown tools: {', '.join(sorted(unknown))}")
    paths = Paths()
    record_env(paths.results / "env.json")
    with RunSummary("sast run") as s:
        if path is not None:
            lang = language or detect_language(path, cfg)
            out_dir = out or paths.sast / "adhoc" / path.resolve().name
            res = run_tools_isolated(path, lang, out_dir, tool_list, cfg, item_id=path.resolve().name,
                                     side="adhoc", force=force)
            _sast_summary(s, path.name, res)
            s.notes.append(f"output: {out_dir}")
            return
        from bench.build import load_items, snapshot_dir

        items = load_items(split)
        if limit:
            items = items[:limit]
        for it in items:
            for side in ("vuln", "fixed"):
                target = snapshot_dir(it["id"], side)
                if not target.exists():
                    s.fail(f"{it['id']}/{side}: snapshot missing (run bench checkout)")
                    continue
                res = run_tools(target, it["language"], paths.sast / it["id"] / side, tool_list, cfg,
                                item_id=it["id"], side=side, force=force)
                _sast_summary(s, f"{it['id']}/{side}", res)


def _sast_summary(s: RunSummary, label: str, res: dict) -> None:
    s.inc("snapshots")
    for tool, r in res.items():
        if r.reason in {'disabled', 'not_applicable'}:
            s.inc(f'{tool} {r.reason}')
        elif r.skipped:
            s.inc(f"{tool} cached")
        elif r.ok:
            s.inc(f"{tool} ok")
        else:
            s.fail(f"{label} {tool}: {(r.error or '')[:200]}")


# ----------------------------------------------------------------------------- Stage C


@context_app.command("build")
def context_build(split: Optional[str] = typer.Option(None), limit: Optional[int] = typer.Option(None),
                  force: bool = typer.Option(False)):
    """Index snapshots: functions, call graph, entry points, sinks."""
    from bench.context import build_all

    with RunSummary("context build") as s:
        build_all(split, limit, force, s)


# ----------------------------------------------------------------------------- Stage D

MODE_HELP = "live: call the API; export: queue requests for offline batch (Kaggle/Colab); cache: cached answers only"


def _client(mode: str):
    from app.core.yaml_configs import load_models_config
    from app.ai.llm import LLMClient

    return LLMClient(load_models_config(), mode=mode, data_root=Paths().root)


@llm_app.command("models")
def llm_models():
    """Verify model ids in models.yaml against the OpenRouter models endpoint."""
    rows = _client("live").verify_models()
    for r in rows:
        ok = {True: "[green]ok[/green]", False: "[red]NOT FOUND[/red]", None: "(self-hosted)"}[r["exists"]]
        console.print(f"{r['id']:55s} {r['backend']:11s} {r['role']:8s} {ok} ctx={r['context']} "
                      f"price={r['prompt_price']}/{r['completion_price']}")


@llm_app.command("triage")
def llm_triage(
    model: str = typer.Option(..., help="Model id from models.yaml"),
    split: Optional[str] = typer.Option("dev"), limit: Optional[int] = typer.Option(None),
    mode: str = typer.Option("live", help=MODE_HELP),
    max_findings: int = typer.Option(10, help="Top-ranked merged SAST findings triaged per snapshot"),
    per_prompt: int = typer.Option(5, help="Findings judged per LLM call"),
    budget_tokens: int = typer.Option(6000, help="Context token budget per finding group (x1.5)"),
):
    """Mode T: classify merged SAST findings as true/false positives."""
    from bench.llm import run_triage

    with RunSummary(f"llm triage {model}") as s:
        run_triage(model, _client(mode), split, limit, max_findings, budget_tokens, s, per_prompt)


@llm_app.command("discover")
def llm_discover(
    model: str = typer.Option(..., help="Model id from models.yaml"),
    split: Optional[str] = typer.Option("dev"), limit: Optional[int] = typer.Option(None),
    mode: str = typer.Option("live", help=MODE_HELP),
    hybrid: bool = typer.Option(False, help="D+: include SAST findings as hints"),
    n_base: int = typer.Option(6, help="Candidate functions for a small repo"),
    n_cap: int = typer.Option(12, help="Max candidate functions per snapshot"),
    per_prompt: int = typer.Option(5, help="Candidate functions per prompt"),
    budget_tokens: int = typer.Option(10000, help="Token budget per prompt"),
):
    """Mode D: hunt for vulnerabilities starting from entry points and sinks."""
    from bench.llm import run_discovery

    with RunSummary(f"llm discover{'+' if hybrid else ''} {model}") as s:
        run_discovery(model, _client(mode), split, limit, hybrid, n_base, n_cap, per_prompt, budget_tokens, s)


@llm_app.command("import")
def llm_import(file: Path = typer.Argument(..., help="responses.jsonl from scripts/kaggle_vllm_batch.py")):
    """Load offline batch responses into the LLM cache."""
    n = _client("cache").import_responses(file)
    console.print(f"imported {n} responses into the cache; re-run the llm command with --mode cache or live")


# ----------------------------------------------------------------------------- Stage E


@eval_app.command("run")
def eval_run(models: Optional[str] = typer.Option(None, help="Comma-separated model ids (default: models.yaml)"),
             all_scope: bool = typer.Option(False, "--all-scope",
                                           help="Treat every file as product code (external corpora)")):
    """Match all outputs to ground truth and compute metrics -> results/metrics.json."""
    from bench.eval.metrics import run_eval
    from app.core.yaml_configs import set_product_scope

    set_product_scope(all_scope)
    with RunSummary("eval run") as s:
        res = run_eval([m for m in models.split(",") if m] if models else None)
        for split, confs in res["metrics"].items():
            if "/" not in split:
                s.inc(f"{split}: configs", len(confs))
        s.notes.append("wrote results/metrics.json and results/item_hits.jsonl")


@eval_app.command("report")
def eval_report():
    """Render results/report.md (+ PNG plots) from metrics.json."""
    from bench.eval.report import write_report

    console.print(f"wrote {write_report()}")


# ----------------------------------------------------------------------------- audit report


@audit_app.command("show")
def audit_show(
    item_id: str = typer.Argument(..., help="Benchmark item id, e.g. js-CVE-2015-3295"),
    side: str = typer.Option("vuln", help="vuln | fixed"),
    model: Optional[str] = typer.Option(None, help="Model whose triage/discovery to include"),
    config: Optional[str] = typer.Option(None, help="S | S+T | S+D | S+T+D | L (default: best available)"),
    top: int = typer.Option(10, help="Findings in the table"),
    details: int = typer.Option(3, help="Findings shown with explanation and code"),
    reveal_gt: bool = typer.Option(False, "--reveal-gt", help="Mark findings that match the known CVE"),
    svg: Optional[Path] = typer.Option(None, help="Also save the terminal output as SVG"),
    md: Optional[Path] = typer.Option(None, help="Also write a Markdown audit document"),
    width: int = typer.Option(120, help="Width for SVG export"),
):
    """Render the security audit for one repository snapshot."""
    from rich.console import Console

    from app.services.report.audit import render, render_markdown, render_to_svg
    from bench.audit import collect

    data = collect(item_id, side, model, config)
    render(data, Console(), top=top, details=details, reveal=reveal_gt)
    if svg:
        render_to_svg(data, svg, width=width, top=top, details=details, reveal=reveal_gt)
        console.print(f"saved {svg}")
    if md:
        md.parent.mkdir(parents=True, exist_ok=True)
        md.write_text(render_markdown(data, top=top, details=max(details, 5), reveal=reveal_gt), encoding="utf-8")
        console.print(f"saved {md}")


if __name__ == "__main__":
    cli()
