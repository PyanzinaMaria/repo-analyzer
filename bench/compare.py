"""Cross-corpus metric comparison: `bench compare DIR... --out FILE` reads results/metrics.json
of every corpus and renders one markdown table per corpus plus a headline summary."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from app.core import io
from app.core.runlog import RunSummary

KEYS = ("recall@1", "recall@10", "mrr", "pair_acc@10", "findings_per_kloc")
FMT = {"recall@1": "{:.0%}", "recall@10": "{:.0%}", "mrr": "{:.2f}", "pair_acc@10": "{:.0%}",
       "findings_per_kloc": "{:.1f}"}
NOTES = [
    "PairAcc applies only to corpora with a fixed side (OWASP and RealVuln are recall-only).",
    "OWASP corpora scan the shared tree once per (repo, commit); the coverage line counts one "
    "observation per item, so scans are reused across category items.",
    "seclens is pending dataset access (gated on HuggingFace); no numbers yet.",
]


def _fmt(v) -> str:
    return "–" if v is None or v != v else FMT[v[0]].format(v[1])


def _pool(metrics: dict) -> dict[str, dict]:
    """Merge per-split config metrics into one row per config, weighted by n.
    aggregate() also emits subgroup keys (`dev/cwe/...`) — only top-level splits are pooled."""
    acc: dict[str, dict] = defaultdict(lambda: defaultdict(float))
    ns: dict[str, int] = defaultdict(int)
    for split, confs in metrics.items():
        if "/" in split:
            continue
        for conf, m in confs.items():
            n = m.get("n") or 0
            ns[conf] += n
            for k in KEYS:
                v = m.get(k)
                if v is not None and v == v:
                    acc[conf][k] += v * n
    return {c: {"n": ns[c], **{k: (row[k] / ns[c] if ns[c] else None) for k in KEYS}}
            for c, row in acc.items()}


def _coverage_line(coverage: dict) -> str:
    """`tool 34/40 ok (6 prepare_error), ...` summed over splits."""
    per_tool: dict[str, tuple[int, dict[str, int]]] = {}
    for confs in coverage.values():
        for tool, counts in confs.items():
            ok, fails = per_tool.get(tool, (0, {}))
            ok += counts.get("ok", 0)
            total = counts.get("applicable", 0)
            for status, n in counts.items():
                if status in ("disabled", "not_applicable", "ok", "applicable", "seconds"):
                    continue
                fails[status] = fails.get(status, 0) + n
            if total or fails:
                per_tool[tool] = (ok, fails)
    parts = []
    for tool, (ok, fails) in sorted(per_tool.items()):
        total = ok + sum(fails.values())
        if not total:
            continue
        line = f"{tool} {ok}/{total} ok"
        if fails:
            line += " (" + ", ".join(f"{n} {s}" for s, n in sorted(fails.items())) + ")"
        parts.append(line)
    return " · ".join(parts)


def write_comparison(roots: list[Path], out: Path) -> Path:
    lines = ["# Benchmark comparison", "",
             "Pooled per-corpus metrics (n-weighted over splits) from `results/metrics.json`; "
             "per-item numbers and confidence intervals live in each corpus's `results/report.md`.", ""]
    for root in roots:
        res = io.read_json(root / "results" / "metrics.json")
        top = [s for s in (res.get("metrics") or {}) if "/" not in s]
        splits = ", ".join(sorted(top)) or "—"
        lines += [f"## {root.name}", "", f"*splits: {splits} · data: `{root}`*", ""]
        lines += ["| config | n | R@1 | R@10 | MRR | PairAcc@10 | findings/KLOC |",
                  "|---|---|---|---|---|---|---|"]
        for conf, m in sorted(_pool(res.get("metrics") or {}).items(),
                              key=lambda kv: (kv[0] != "S", kv[0])):
            lines.append("| " + " | ".join([conf, str(m["n"])] +
                                           [_fmt((k, m.get(k))) for k in KEYS]) + " |")
        lines += ["", f"*scan coverage:* {_coverage_line(res.get('scan_coverage') or {})}", ""]
    lines += ["## Notes", ""] + [f"- {n}" for n in NOTES] + [""]
    io.atomic_write_text(out, "\n".join(lines) + "\n")
    return out


def compare(roots: list[Path], out: Path, summary: RunSummary | None = None) -> Path:
    summary = summary or RunSummary("bench compare")
    for r in roots:
        summary.inc(f"{r.name}: configs")
    return write_comparison(roots, out)
