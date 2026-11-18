"""Figures for docs/REPORT.md, built from $SECBENCH_DATA (no API calls).

    scripts/sb-python scripts/make_report_figures.py      (or: ~/.venvs/repo-analyzer/bin/python ...)
"""

from __future__ import annotations

import json
import os
import sys
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
from bench.config import Paths  # noqa: E402

OUT = REPO / "docs" / "img"

# Reference palette (dataviz skill, light mode): series slots 1-3, text and surface tokens.
SURFACE, TEXT, TEXT2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
S1, S2, S3 = "#2a78d6", "#eb6834", "#1baf7a"

plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "axes.edgecolor": GRID, "axes.labelcolor": TEXT2, "xtick.color": TEXT2, "ytick.color": TEXT,
    "text.color": TEXT, "font.size": 10, "axes.titlesize": 11, "axes.titleweight": "bold",
    "axes.spines.top": False, "axes.spines.right": False, "axes.spines.left": False,
})


def _hbar(ax, labels, values, fmt, color=S1, xmax=None, title="", xlabel="", log=False):
    y = range(len(labels))
    ax.barh(list(y), values, color=color, height=0.55, edgecolor=SURFACE, linewidth=2)
    ax.set_yticks(list(y), labels)
    ax.invert_yaxis()
    ax.tick_params(axis="y", length=0)
    ax.grid(axis="x", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    top = xmax or (max(values) * 1.18 if values and max(values) > 0 else 1)
    if log:
        ax.set_xscale("log")
        ax.set_xlim(1, top)
    else:
        ax.set_xlim(0, top)
    for i, v in enumerate(values):
        x = v * 1.12 if log else v + top * 0.015
        ax.text(x, i, fmt(v), va="center", fontsize=9, color=TEXT2)
    ax.set_title(title, loc="left")
    ax.set_xlabel(xlabel)


def fig_sast(metrics: dict, group: str = "dev") -> str | None:
    m = metrics.get(group, {})
    confs = [c for c in ["S", "S-codeql", "S-eslint", "S-bandit", "S-semgrep"] if c in m]
    if not confs:
        return None
    names = {"S": "All tools merged (S)", "S-codeql": "CodeQL", "S-eslint": "ESLint-security",
             "S-bandit": "Bandit (Python)", "S-semgrep": "Semgrep"}
    labels = [f"{names[c]}  (n={m[c]['n']})" for c in confs]
    fig, (a, b) = plt.subplots(1, 2, figsize=(10, 3.2), gridspec_kw={"wspace": 0.75})
    _hbar(a, labels, [m[c]["recall@10"] for c in confs], lambda v: f"{100 * v:.0f}%", xmax=1,
          title="Known vulnerability in top 10 (recall@10)", xlabel="share of items · higher is better")
    _hbar(b, [""] * len(confs), [m[c]["findings_per_kloc"] for c in confs], lambda v: f"{v:.1f}", color=S2,
          title="Findings per 1,000 lines", xlabel="auditor burden · lower is better")
    fig.suptitle(f"SAST baseline on the {group} split", x=0.02, ha="left", fontsize=12, fontweight="bold")
    fig.subplots_adjust(top=0.78, bottom=0.2, left=0.22, right=0.97)
    p = OUT / f"sast_baseline_{group}.png"
    fig.savefig(p, dpi=150)
    plt.close(fig)
    return p.name


def fig_benchmark(items: list[dict]) -> str:
    splits = ["dev", "test", "post_cutoff", "extra"]
    langs = [("python", S1, "Python"), ("javascript", S2, "JavaScript"), ("typescript", S3, "TypeScript")]
    fig, (a, b) = plt.subplots(1, 2, figsize=(10, 3.6), gridspec_kw={"wspace": 0.45, "width_ratios": [1, 1.2]})
    left = [0] * len(splits)
    for lang, color, label in langs:
        vals = [sum(1 for it in items if it["split"] == s and it["language"] == lang) for s in splits]
        a.barh(splits, vals, left=left, color=color, height=0.55, edgecolor=SURFACE, linewidth=2, label=label)
        for i, v in enumerate(vals):
            if v >= 6:
                a.text(left[i] + v / 2, i, str(v), ha="center", va="center", color="white", fontsize=9)
        left = [x + v for x, v in zip(left, vals)]
    for i, tot in enumerate(left):
        a.text(tot + 1.5, i, str(tot), va="center", fontsize=9, color=TEXT2)
    a.invert_yaxis()
    a.tick_params(axis="y", length=0)
    a.grid(axis="x", color=GRID, linewidth=0.8)
    a.set_axisbelow(True)
    a.set_title("Items by split and language", loc="left")
    a.legend(frameon=False, loc="lower right", fontsize=9)
    a.set_xlim(0, max(left) * 1.15)
    cwes = Counter(it["cwe"][0] for it in items if it["split"] in ("dev", "test", "post_cutoff"))
    top = cwes.most_common()
    _hbar(b, [c for c, _ in top], [n for _, n in top], str, title="Primary CWE (dev + test + post_cutoff)")
    b.tick_params(axis="y", labelsize=8)
    fig.subplots_adjust(top=0.88, bottom=0.08, left=0.1, right=0.97)
    p = OUT / "benchmark_composition.png"
    fig.savefig(p, dpi=150)
    plt.close(fig)
    return p.name


def fig_funnel(paths: Paths, model: str | None) -> str | None:
    """Dev split: raw SAST findings -> product code -> reviewed by triage -> kept as real/unsure."""
    from app.core import io
    from bench.build import load_items
    from bench.llm import out_dir
    from bench.rank import load_merged

    raw = prod = reviewed = kept = snaps = 0
    for it in load_items("dev", paths):
        for side in ("vuln", "fixed"):
            f = paths.sast / it["id"] / side / "merged.jsonl"
            t = out_dir(model, "triage", paths) / it["id"] / f"{side}.jsonl" if model else None
            if not f.exists() or t is None or not t.exists():
                continue  # only snapshots that went through triage, so the stages are comparable
            snaps += 1
            raw += len(io.read_jsonl(f))
            prod += len(load_merged(it["id"], side, paths) or [])
            for r in io.read_jsonl(t):
                if r.get("result"):
                    reviewed += 1
                    kept += r["score"] > 0
    if not raw:
        return None
    labels = ["SAST findings (merged)", "in product code", "reviewed by LLM triage", "kept as real / unsure"]
    vals = [raw, prod, reviewed, kept]
    fig, ax = plt.subplots(figsize=(8, 2.6))
    _hbar(ax, labels, vals, lambda v: f"{v:,}", xmax=raw * 4, log=True,
          title=f"What the auditor has to read ({snaps} triaged dev snapshots)",
          xlabel="findings (log scale) · triage reviews the top 10 per snapshot")
    fig.subplots_adjust(left=0.27, right=0.97, top=0.85, bottom=0.22)
    p = OUT / "triage_funnel_dev.png"
    fig.savefig(p, dpi=150)
    plt.close(fig)
    return p.name


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    paths = Paths()
    from app.core import io

    items = io.read_jsonl(paths.benchmark)
    metrics = json.loads((paths.results / "metrics.json").read_text())
    model = os.environ.get("REPORT_MODEL", "nvidia/nemotron-3-ultra-550b-a55b:free")
    made = [fig_benchmark(items), fig_sast(metrics["metrics"]), fig_funnel(paths, model)]
    print("\n".join(str(OUT / m) for m in made if m))


if __name__ == "__main__":
    main()
