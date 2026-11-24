"""Cross-corpus DAST comparison: `bench dast compare DIR... --out FILE` reads
results/dast_metrics.json of every corpus and renders one markdown table per corpus.

Kept separate from the SAST `bench compare` because the metric schemas differ
(endpoint-level TP/FP/FN + FP-rate vs recall@k / MRR)."""

from __future__ import annotations

from pathlib import Path

from app.core import io
from app.core.runlog import RunSummary
from bench.dast.eval import _fmt_seconds, _pct

NOTES = [
    "OWASP corpora score per test case: URL -> BenchmarkTestNNNNN -> expectedresults CSV "
    "(true/false + CWE); non-test findings count as FP and are listed separately.",
    "RealVuln has no URL-level ground truth, so it is scored per app by CWE overlap "
    "(cwe_overlap families); precision there is a proxy, not a true FP count.",
    "OFFAT requires an OpenAPI spec: generated from pinned routes for OWASP, probed live "
    "for RealVuln (apps without a spec are skipped as no_openapi).",
    "Each tool gets a fixed time budget per target (config/dast.yaml scan_timeout_s); "
    "ZAP/Nikto caps limit coverage on the 2740-endpoint BenchmarkJava.",
]


def write_comparison(roots: list[Path], out: Path) -> Path:
    lines = ["# DAST benchmark comparison", "",
             "Per-corpus metrics from `results/dast_metrics.json` (`python -m bench dast eval <kind>`); "
             "per-tool raw runs live under each corpus's `dast/` directory.", ""]
    for root in roots:
        mf = root / "results" / "dast_metrics.json"
        if not mf.is_file():
            lines += [f"## {root.name}", "", "*нет dast_metrics.json — прогоните `bench dast eval`*", ""]
            continue
        res = io.read_json(mf)
        mode = res.get("mode")
        lines += [f"## {root.name}", "",
                  f"*mode: {mode} · generated: {res.get('generated_at')} · "
                  f"лимит: {res.get('scan_timeout_s')} c на тул/цель*", ""]
        if mode == "owasp":
            lines += ["| tool | TP | FP | FN | Precision | Recall | F1 | TP-rate | FP-rate | cwe-agree | non-test | время |",
                      "|---|---|---|---|---|---|---|---|---|---|---|---|"]
            for tool, m in sorted((res.get("metrics") or {}).items()):
                lines.append(
                    f"| {tool} | {m['tp']} | {m['fp']} | {m['fn']} | {_pct(m['precision'])} | "
                    f"{_pct(m['recall'])} | {_pct(m['f1'])} | {_pct(m.get('tp_rate'))} | "
                    f"{_pct(m.get('fp_rate'))} | {_pct(m.get('cwe_agreement'))} | "
                    f"{m.get('non_test_findings', '–')} | {_fmt_seconds(m.get('seconds'))} |")
        else:
            lines += ["| tool | items | hit | Recall(items) | TP(findings) | FP | Precision | время |",
                      "|---|---|---|---|---|---|---|---|"]
            for tool, m in sorted((res.get("metrics") or {}).items()):
                lines.append(
                    f"| {tool} | {m.get('n_items', '–')} | {m.get('items_hit', '–')} | "
                    f"{_pct(m.get('recall_items'))} | {m['tp']} | {m['fp']} | "
                    f"{_pct(m['precision'])} | {_fmt_seconds(m.get('seconds'))} |")
        cov = res.get("coverage") or {}
        if cov:
            parts = [f"{tool}: " + (", ".join(f"{n} {k}" for k, n in sorted(counts.items())) or "не запускался")
                     for tool, counts in sorted(cov.items())]
            lines += ["", "*coverage:* " + " · ".join(parts), ""]
    lines += ["## Notes", ""] + [f"- {n}" for n in NOTES] + [""]
    io.atomic_write_text(out, "\n".join(lines) + "\n")
    return out


def compare(roots: list[Path], out: Path, summary: RunSummary | None = None) -> Path:
    summary = summary or RunSummary("dast compare")
    for r in roots:
        summary.inc(f"{r.name}: corpora")
    return write_comparison(roots, out)
