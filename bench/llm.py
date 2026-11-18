"""`python -m bench llm triage|discover`: run the LLM modes over benchmark snapshots (both sides).

Outputs: $SECBENCH_DATA/llm/<model>/<mode>/<item>/<side>.jsonl. Snapshots with prompts still pending
(export mode) are not written, so evaluation never scores partial results.
"""

from __future__ import annotations

from pathlib import Path

from app.ai.discovery import discover_functions
from app.ai.llm import BudgetExceeded, DailyLimitReached, LLMClient, UpstreamUnavailable, model_slug
from app.ai.prompting import prompt_version
from app.ai.triage import triage_findings
from app.core import io
from app.core.runlog import RunSummary, log
from app.sast.normalize import rank_sast
from bench.build import load_items
from bench.config import Paths


def out_dir(model_id: str, mode: str, paths: Paths | None = None) -> Path:
    return (paths or Paths()).root / "llm" / model_slug(model_id) / mode


# ----------------------------------------------------------------------------- triage


def triage_snapshot(client: LLMClient, model_id: str, item: dict, side: str, max_findings: int,
                    budget_tokens: int, paths: Paths, summary: RunSummary, per_prompt: int = 5) -> list[dict]:
    from bench.context import load_snapshot
    from bench.rank import load_merged

    merged = load_merged(item["id"], side, paths)
    if merged is None:
        summary.fail(f"{item['id']}/{side}: no SAST output")
        return []
    findings = rank_sast(merged)[:max_findings]
    snap = load_snapshot(item["id"], side, paths)
    return triage_findings(client, model_id, snap, item["language"], findings, budget_tokens, per_prompt,
                           summary, tag=f"triage:{item['id']}:{side}")


def run_triage(model_id: str, client: LLMClient, split: str | None, limit: int | None, max_findings: int,
               budget_tokens: int, summary: RunSummary, per_prompt: int = 5) -> None:
    paths = Paths()
    od = out_dir(model_id, "triage", paths)
    items = load_items(split, paths)[: limit or None]
    for it in items:
        for side in ("vuln", "fixed"):
            try:
                rows = triage_snapshot(client, model_id, it, side, max_findings, budget_tokens, paths, summary,
                                       per_prompt)
            except (DailyLimitReached, BudgetExceeded, UpstreamUnavailable) as e:
                summary.notes.append(f"stopped: {e}")
                log.warning("stopping: %s", e)
                return
            out = od / it["id"] / f"{side}.jsonl"
            if any(r["pending"] for r in rows):
                # incomplete (export mode): never leave a partial result that eval would score
                out.unlink(missing_ok=True)
                summary.inc("snapshots pending")
                continue
            io.write_jsonl(out, rows)
            summary.inc("snapshots")
    io.write_json(od / "meta.json", {"model": model_id, "prompt_version": prompt_version("triage"),
                                     "max_findings": max_findings, "budget_tokens": budget_tokens,
                                     "per_prompt": per_prompt})


# ----------------------------------------------------------------------------- discovery


def discover_snapshot(client: LLMClient, model_id: str, item: dict, side: str, hybrid: bool, n_base: int,
                      n_cap: int, per_prompt: int, budget_tokens: int, paths: Paths,
                      summary: RunSummary) -> list[dict] | None:
    """Ranked findings, or None when some prompts are still pending (export mode)."""
    from bench.context import load_snapshot
    from bench.rank import load_merged

    snap = load_snapshot(item["id"], side, paths)
    merged = (load_merged(item["id"], side, paths) or []) if hybrid else []
    return discover_functions(client, model_id, snap, item["language"], item["loc"], merged, n_base, n_cap,
                              per_prompt, budget_tokens, summary,
                              tag=f"discover{'+' if hybrid else ''}:{item['id']}:{side}")


def run_discovery(model_id: str, client: LLMClient, split: str | None, limit: int | None, hybrid: bool,
                  n_base: int, n_cap: int, per_prompt: int, budget_tokens: int, summary: RunSummary) -> None:
    paths = Paths()
    mode = "discovery_hybrid" if hybrid else "discovery"
    od = out_dir(model_id, mode, paths)
    for it in load_items(split, paths)[: limit or None]:
        for side in ("vuln", "fixed"):
            try:
                rows = discover_snapshot(client, model_id, it, side, hybrid, n_base, n_cap, per_prompt,
                                         budget_tokens, paths, summary)
            except (DailyLimitReached, BudgetExceeded, UpstreamUnavailable) as e:
                summary.notes.append(f"stopped: {e}")
                log.warning("stopping: %s", e)
                return
            except FileNotFoundError as e:
                summary.fail(f"{it['id']}/{side}: missing input ({e.filename}); run sast/context first")
                continue
            out = od / it["id"] / f"{side}.jsonl"
            if rows is None:
                # incomplete (export mode): never leave a partial result that eval would score
                out.unlink(missing_ok=True)
                summary.inc("snapshots pending")
                continue
            io.write_jsonl(out, rows)
            summary.inc("snapshots")
    io.write_json(od / "meta.json", {"model": model_id, "prompt_version": prompt_version("discovery"),
                                     "hybrid": hybrid, "n_base": n_base, "n_cap": n_cap, "per_prompt": per_prompt,
                                     "budget_tokens": budget_tokens})
