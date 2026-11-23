"""results/report.md (spec §7.4), built only from files on disk (no API calls)."""

from __future__ import annotations

import math
from pathlib import Path

from app.core import io
from bench.build import load_items
from bench.config import Paths
from bench.llm import out_dir


def _f(x, pct: bool = False) -> str:
    if x is None or (isinstance(x, float) and math.isnan(x)):
        return "–"
    return f"{100 * x:.0f}%" if pct else f"{x:.2f}"


def _ci(ci) -> str:
    if not ci or any(isinstance(v, float) and math.isnan(v) for v in ci):
        return ""
    return f" [{100 * ci[0]:.0f}–{100 * ci[1]:.0f}]"


def _table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return out


def _plots(metrics: dict, group: str, ks: list[int], results: Path) -> list[str]:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    out = []
    confs = metrics.get(group, {})
    if not confs:
        return out
    fig, ax = plt.subplots(figsize=(7, 4.2))
    for conf, m in sorted(confs.items()):
        if conf.startswith("S-"):
            continue
        ax.plot(ks, [m[f"recall@{k}"] for k in ks], marker="o", label=f"{conf} (n={m['n']})")
    ax.set_xlabel("k (findings shown to auditor)")
    ax.set_ylabel("recall@k (function hit)")
    ax.set_ylim(0, 1)
    ax.set_xticks(ks)
    ax.grid(alpha=0.3)
    ax.legend(fontsize=7, loc="lower right")
    ax.set_title(f"recall@k — {group}")
    p = results / f"recall_at_k_{group}.png"
    fig.tight_layout()
    fig.savefig(p, dpi=130)
    plt.close(fig)
    out.append(p.name)

    cwe_groups = sorted(g for g in metrics if g.startswith(f"{group}/cwe/"))
    conf_names = [c for c in sorted(confs) if not c.startswith("S-")]
    if cwe_groups and conf_names:
        import numpy as np

        data = np.array([[metrics[g].get(c, {}).get("recall@10", np.nan) for c in conf_names] for g in cwe_groups])
        fig, ax = plt.subplots(figsize=(1.2 + 1.1 * len(conf_names), 0.9 + 0.4 * len(cwe_groups)))
        im = ax.imshow(data, vmin=0, vmax=1, cmap="viridis", aspect="auto")
        ax.set_xticks(range(len(conf_names)), [c.replace("@", "\n@") for c in conf_names], fontsize=6)
        ax.set_yticks(range(len(cwe_groups)), [g.split("/")[-1] for g in cwe_groups], fontsize=7)
        for i in range(data.shape[0]):
            for j in range(data.shape[1]):
                if not np.isnan(data[i, j]):
                    ax.text(j, i, f"{data[i, j]:.2f}", ha="center", va="center", fontsize=6,
                            color="white" if data[i, j] < 0.5 else "black")
        fig.colorbar(im, ax=ax, label="recall@10")
        ax.set_title(f"recall@10 by CWE — {group}", fontsize=9)
        p = results / f"cwe_heatmap_{group}.png"
        fig.tight_layout()
        fig.savefig(p, dpi=130)
        plt.close(fig)
        out.append(p.name)
    return out


def _examples(paths: Paths, models: list[str], limit: int = 5) -> list[str]:
    """Qualitative examples: SAST miss caught by LLM, FP removed by triage, likely hallucination."""
    hits = io.read_jsonl(paths.results / "item_hits.jsonl")
    by = {(r["item"], r["config"]): r for r in hits}
    items = {it["id"]: it for it in load_items(None, paths)}
    lines: list[str] = []
    found = 0
    for model in models:
        for (item, conf), r in by.items():
            if found >= limit:
                break
            if conf != f"L@{model}" or not r["func_rank"] or r["func_rank"] > 5:
                continue
            s = by.get((item, "S"))
            if s and s["func_rank"] and s["func_rank"] <= 10:
                continue
            rows = io.read_jsonl(out_dir(model, "discovery", paths) / item / "vuln.jsonl")
            v = rows[r["func_rank"] - 1] if len(rows) >= r["func_rank"] else None
            if v:
                lines += [f"**SAST miss caught by LLM** — `{item}` ({items[item]['cwe'][0]}), {model}, rank {r['func_rank']}: "
                          f"{v['file']}:{v['start_line']} — *{v['title']}*. {v['explanation'][:400]}", ""]
                found += 1
        tri = out_dir(model, "triage", paths)
        if tri.exists() and found < limit:
            for item in sorted(items):
                p = tri / item / "fixed.jsonl"
                if not p.exists():
                    continue
                fp = next((x for x in io.read_jsonl(p) if x.get("result")
                           and x["result"]["verdict"] == "false_positive"), None)
                if fp:
                    lines += [f"**FP removed by triage** — `{item}` fixed side, {model}: {fp['file']}:{fp['start_line']} "
                              f"({', '.join(fp['tools'])}). {fp['result']['explanation'][:400]}", ""]
                    found += 1
                    break
        disc = out_dir(model, "discovery", paths)
        if disc.exists() and found < limit:
            for (item, conf), r in by.items():
                if conf != f"L@{model}" or r["func_rank"]:
                    continue
                rows = io.read_jsonl(disc / item / "vuln.jsonl")
                top = rows[0] if rows else None
                if top and top["confidence"] >= 0.8:
                    lines += [f"**Confident miss / possible hallucination** — `{item}`, {model}: "
                              f"{top['file']}:{top['start_line']} *{top['title']}* (conf {top['confidence']:.2f}) — "
                              f"not the known vulnerability; needs manual review (could also be a real new bug).", ""]
                    found += 1
                    break
    return lines or ["(no LLM outputs yet)"]


def write_report(paths: Paths | None = None) -> Path:
    paths = paths or Paths()
    res = io.read_json(paths.results / "metrics.json")
    metrics, models = res["metrics"], res["models"]
    ks = res["eval_config"]["ks"]
    lines = ["# Results report", "",
             "Generated by `python -m bench eval report` from cached outputs (no API calls).", ""]
    stats = paths.results / "benchmark_stats.md"
    if stats.exists():
        lines += ["## Benchmark", "", "See [benchmark_stats.md](benchmark_stats.md).", ""]

    for group in [g for g in ("test", "post_cutoff", "dev") if g in metrics]:
        warn = " — ⚠️ dev split: for prompt iteration only, not final numbers" if group == "dev" else ""
        lines += [f"## Main results: {group}{warn}", ""]
        header = ["config", "n"] + [f"R@{k}" for k in ks] + ["MRR", "pairs", "PairAcc@10", "line R@10", "findings/KLOC", "CWE agree"]
        rows = []
        for conf, m in sorted(metrics[group].items(), key=lambda kv: (kv[0].startswith("S-"), kv[0])):
            rows.append([conf, m["n"]] + [_f(m[f"recall@{k}"], True) + (_ci(m.get("recall@10_ci")) if k == 10 else "")
                                          for k in ks]
                        + [_f(m["mrr"]) + _ci(m.get("mrr_ci")).replace("%", ""), m.get("n_paired", "–"), _f(m["pair_acc@10"], True)
                           + _ci(m.get("pair_acc@10_ci")), _f(m["line_recall@10"], True),
                           _f(m["findings_per_kloc"]), _f(m["cwe_agreement"], True)])
        lines += _table(header, rows) + [""]
        for fam in sorted(key.split("/")[1] for key in metrics if key.startswith(group + "/") and key.count("/") == 1):
            sub = metrics.get(f"{group}/{fam}")
            if sub:
                lines += [f"**{group} / {fam}**: " + ", ".join(
                    f"{c} R@10={_f(m['recall@10'], True)} (n={m['n']})" for c, m in sorted(sub.items())
                    if not c.startswith("S-")), ""]
        for img in _plots(metrics, group, ks, paths.results):
            lines += [f"![{img}]({img})", ""]

    if coverage := res.get("scan_coverage"):
        lines += ["## SAST execution (one observation per revision)", ""]
        rows = []
        for split, tools in coverage.items():
            for tool, counts in sorted(tools.items()):
                errors = sum(n for s, n in counts.items() if s not in
                             {"ok", "not_applicable", "disabled", "applicable", "timeout", "seconds"})
                rows.append([split, tool, counts.get("applicable", 0), counts.get("ok", 0),
                             counts.get("not_applicable", 0), counts.get("disabled", 0),
                             counts.get("timeout", 0), errors, _f(counts["seconds"])])
        lines += _table(["split", "tool", "applicable", "ok", "N/A", "disabled", "timeouts", "errors", "seconds"], rows) + [""]
    if pairs := res.get("paired_tools"):
        k = res["eval_config"]["comparison_k"]
        lines += [f"## Paired tool comparison on common items (hits at {k})", ""]
        lines += _table(["split", "A", "B", "n", "A hits", "B hits", "p"],
                        [[r["split"], r["a"], r["b"], r["n"], r["hits_a"], r["hits_b"], _f(r["p_value"])]
                         for r in pairs]) + [""]

    sig = res.get("significance_vs_S", {})
    if sig:
        lines += ["## Paired comparison vs `S` (McNemar exact, recall@10)", ""]
        rows = [[split, conf, v["n"], v["a_only"], v["b_only"], f"{v['p_value']:.3g}"]
                for split, d in sig.items() for conf, v in sorted(d.items()) if not conf.startswith("S-")]
        lines += _table(["split", "config", "n", "S only", "config only", "p"], rows) + [""]

    if res.get("triage"):
        lines += ["## Triage quality (presumed labels)", ""]
        rows = [[m, _f(v["precision"]), _f(v["recall"]), _f(v["f1"]), v["tp"], v["fp"], v["fn"], v["negatives"],
                 _f(v["fp_reduction"], True)] for m, v in res["triage"].items()]
        lines += _table(["model", "P", "R", "F1", "TP", "FP", "FN", "neg", "FP reduction"], rows) + [""]

    if res.get("costs"):
        lines += ["## Cost", ""]
        rows = [[m, v["calls"], v["cached_calls"], v["prompt_tokens"], v["completion_tokens"],
                 f"${v['cost_usd']:.4f}", f"{v['calls_per_item']:.1f}"] for m, v in res["costs"].items()]
        lines += _table(["model", "API calls", "cache hits", "prompt tok", "completion tok", "USD", "calls/item"],
                        rows) + [""]

    if res.get("contamination"):
        lines += ["## Contamination check (test vs post_cutoff, recall@10)", ""]
        rows = [[k, _f(v["test"], True), _f(v["post_cutoff"], True), _f(v["gap"]), "⚠️" if v["flag"] else ""]
                for k, v in res["contamination"].items()]
        lines += _table(["config", "test", "post_cutoff", "gap", "flag"], rows) + [""]

    lines += ["## Qualitative examples", ""] + _examples(paths, models)
    out = paths.results / "report.md"
    io.atomic_write_text(out, "\n".join(lines) + "\n")
    return out
