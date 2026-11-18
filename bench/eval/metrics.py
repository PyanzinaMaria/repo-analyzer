"""Metrics (spec §7.2–7.3): recall@k, MRR, PairAcc, burden, triage quality, bootstrap CIs, McNemar."""

from __future__ import annotations

import csv
from collections import defaultdict
from functools import lru_cache
from pathlib import Path

import numpy as np
from scipy.stats import binomtest

from app.core import io
from bench.build import load_items
from app.core.yaml_configs import load_models_config
from bench.config import EvalConfig, Paths, load_eval_config
from bench.eval.match import first_hits, flagged_within, gt_spans, line_hit
from bench.llm import out_dir
from bench.rank import build_rankings


# ----------------------------------------------------------------------------- pure metric functions


def recall_at_k(ranks: list[int | None], k: int) -> float:
    return float(np.mean([r is not None and r <= k for r in ranks])) if ranks else float("nan")


def mrr(ranks: list[int | None]) -> float:
    return float(np.mean([1.0 / r if r else 0.0 for r in ranks])) if ranks else float("nan")


def pair_acc(vuln_hit: list[bool], fixed_flag: list[bool]) -> float:
    if not vuln_hit:
        return float("nan")
    return float(np.mean([v and not f for v, f in zip(vuln_hit, fixed_flag)]))


def bootstrap_ci(values: list[float], n: int = 10000, seed: int = 0, alpha: float = 0.05) -> tuple[float, float]:
    if not values:
        return float("nan"), float("nan")
    arr = np.asarray(values, dtype=float)
    rng = np.random.default_rng(seed)
    means = arr[rng.integers(0, len(arr), size=(n, len(arr)))].mean(axis=1)
    return float(np.quantile(means, alpha / 2)), float(np.quantile(means, 1 - alpha / 2))


def mcnemar(a: list[bool], b: list[bool]) -> dict:
    """Exact McNemar test on paired hit/miss outcomes."""
    b01 = sum(1 for x, y in zip(a, b) if x and not y)
    b10 = sum(1 for x, y in zip(a, b) if not x and y)
    n = b01 + b10
    p = binomtest(min(b01, b10), n, 0.5).pvalue if n else 1.0
    return {"a_only": b01, "b_only": b10, "p_value": float(p)}


def prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else float("nan")
    r = tp / (tp + fn) if tp + fn else float("nan")
    f1 = 2 * p * r / (p + r) if p == p and r == r and p + r else float("nan")
    return {"precision": p, "recall": r, "f1": f1, "tp": tp, "fp": fp, "fn": fn}


# ----------------------------------------------------------------------------- data collection


@lru_cache(maxsize=4096)
def _resolver(item_id: str, side: str, root: str):
    p = Path(root) / item_id / side / "index.json"
    if not p.exists():
        return None
    from app.context.index import load_index

    idx = load_index(p)

    def resolve(file: str, line: int):
        fn = idx.function_at(file, line)
        return (fn.start, fn.end) if fn else None

    return resolve


def model_ids() -> list[str]:
    return [m.id for m in load_models_config().models]


def collect_item_hits(cfg: EvalConfig, models: list[str], paths: Paths) -> list[dict]:
    rows = []
    for it in load_items(None, paths):
        gts_v, gts_f = gt_spans(it, "vuln"), gt_spans(it, "fixed")
        rv = _resolver(it["id"], "vuln", str(paths.context))
        rf = _resolver(it["id"], "fixed", str(paths.context))
        ranks_v = build_rankings(it["id"], "vuln", models, paths)
        ranks_f = build_rankings(it["id"], "fixed", models, paths)
        for key, ranked in ranks_v.items():
            hi = first_hits(ranked, gts_v, cfg.line_tol, rv, it["cwe"], cfg.max_function_lines)
            fixed_list = ranks_f.get(key)
            row = {
                "item": it["id"], "split": it["split"], "language": it["language"],
                "family": "python" if it["language"] == "python" else "js", "cwe": it["cwe"][0],
                "loc": it["loc"], "config": key,
                "func_rank": hi.func_rank, "line_rank": hi.line_rank, "long_fn": hi.func_hit_long_fn,
                "cwe_agree": hi.cwe_agree, "n_findings": len(ranked),
                "has_fixed": fixed_list is not None,
            }
            for k in (10, None):
                tag = "all" if k is None else str(k)
                row[f"fixed_flag@{tag}"] = (flagged_within(fixed_list, gts_f, k, cfg.line_tol, rf)
                                            if fixed_list is not None and gts_f else False)
                row[f"vuln_flag@{tag}"] = hi.func_rank is not None and (k is None or hi.func_rank <= k)
            rows.append(row)
    return rows


def aggregate(rows: list[dict], cfg: EvalConfig) -> dict:
    """{group: {config: metrics}} for groups: split, split/family, split/cwe."""
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        groups[r["split"]].append(r)
        groups[f"{r['split']}/{r['family']}"].append(r)
        groups[f"{r['split']}/cwe/{r['cwe']}"].append(r)
    out: dict[str, dict] = {}
    for g, rs in groups.items():
        by_cfg: dict[str, list[dict]] = defaultdict(list)
        for r in rs:
            by_cfg[r["config"]].append(r)
        out[g] = {}
        for conf, cr in sorted(by_cfg.items()):
            fr = [r["func_rank"] for r in cr]
            lr = [r["line_rank"] for r in cr]
            m = {"n": len(cr)}
            for k in cfg.ks:
                m[f"recall@{k}"] = recall_at_k(fr, k)
                m[f"line_recall@{k}"] = recall_at_k(lr, k)
            m["mrr"] = mrr(fr)
            paired = [r for r in cr if r["has_fixed"]]
            for tag in ("10", "all"):
                m[f"pair_acc@{tag}"] = pair_acc([r[f"vuln_flag@{tag}"] for r in paired],
                                                [r[f"fixed_flag@{tag}"] for r in paired])
            kloc = sum(r["loc"] for r in cr) / 1000 or 1
            m["findings_per_kloc"] = sum(r["n_findings"] for r in cr) / kloc
            m["findings_per_kloc@20"] = sum(min(r["n_findings"], 20) for r in cr) / kloc
            m["long_fn_hits"] = sum(1 for r in cr if r["long_fn"])
            agree = [r["cwe_agree"] for r in cr if r["cwe_agree"] is not None]
            m["cwe_agreement"] = float(np.mean(agree)) if agree else float("nan")
            if len(g.split("/")) == 1:   # CIs only for top-level split groups
                m["recall@10_ci"] = bootstrap_ci([1.0 if (x and x <= 10) else 0.0 for x in fr],
                                                 cfg.bootstrap_resamples)
                m["mrr_ci"] = bootstrap_ci([1.0 / x if x else 0.0 for x in fr], cfg.bootstrap_resamples)
                m["pair_acc@10_ci"] = bootstrap_ci(
                    [1.0 if (r["vuln_flag@10"] and not r["fixed_flag@10"]) else 0.0 for r in paired],
                    cfg.bootstrap_resamples)
            out[g][conf] = m
    return out


def significance(rows: list[dict], baseline: str = "S", k: int = 10) -> dict:
    out: dict[str, dict] = {}
    by_split: dict[str, dict[str, dict[str, bool]]] = defaultdict(lambda: defaultdict(dict))
    for r in rows:
        by_split[r["split"]][r["config"]][r["item"]] = r["func_rank"] is not None and r["func_rank"] <= k
    for split, confs in by_split.items():
        base = confs.get(baseline)
        if not base:
            continue
        out[split] = {}
        for conf, hits in confs.items():
            if conf == baseline:
                continue
            common = sorted(set(base) & set(hits))
            if common:
                res = mcnemar([base[i] for i in common], [hits[i] for i in common])
                out[split][conf] = {**res, "n": len(common)}
    return out


def triage_quality(models: list[str], cfg: EvalConfig, paths: Paths) -> dict:
    """Positives: triaged findings on the vuln side that hit GT (line level).
    Presumed negatives: findings on the fixed side at the GT location, and findings > 50 lines from any GT."""
    out = {}
    items = {it["id"]: it for it in load_items(None, paths)}
    for model in models:
        base = out_dir(model, "triage", paths)
        if not base.exists():
            continue
        tp = fp = fn = 0
        neg_total = neg_kept = 0
        for item_id, it in items.items():
            for side in ("vuln", "fixed"):
                p = base / item_id / f"{side}.jsonl"
                if not p.exists():
                    continue
                gts = gt_spans(it, side)
                for r in io.read_jsonl(p):
                    if r.get("result") is None:
                        continue
                    e = {"file": r["file"], "start_line": r["start_line"], "end_line": r["end_line"]}
                    near = any(line_hit(e, g, cfg.line_tol) for g in gts)
                    far = not any(line_hit(e, g, 50) for g in gts)
                    says_tp = r["result"]["verdict"] == "true_positive"
                    kept = r["result"]["verdict"] != "false_positive"
                    if side == "vuln" and near:
                        tp += says_tp
                        fn += not says_tp
                    elif (side == "fixed" and near) or far:
                        fp += says_tp
                        neg_total += 1
                        neg_kept += kept
        out[model] = {**prf(tp, fp, fn), "negatives": neg_total, "negatives_kept": neg_kept,
                      "fp_reduction": 1 - neg_kept / neg_total if neg_total else float("nan"),
                      "labels": "presumed (validate a sample by hand)"}
    return out


def costs(paths: Paths) -> dict:
    p = paths.results / "llm_costs.csv"
    out: dict[str, dict] = defaultdict(lambda: {"calls": 0, "cached_calls": 0, "cost_usd": 0.0,
                                                "prompt_tokens": 0, "completion_tokens": 0, "items": set()})
    if not p.exists():
        return {}
    with open(p, encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            m = out[row["model"]]
            if row["cached"] == "1":
                m["cached_calls"] += 1
                continue
            m["calls"] += 1
            m["cost_usd"] += float(row["cost_usd"] or 0)
            m["prompt_tokens"] += int(row["prompt_tokens"] or 0)
            m["completion_tokens"] += int(row["completion_tokens"] or 0)
            parts = row["tag"].split(":")
            if len(parts) >= 2:
                m["items"].add(parts[1])
    res = {}
    for model, m in out.items():
        n_items = len(m.pop("items")) or 1
        res[model] = {**m, "items": n_items, "cost_per_item": m["cost_usd"] / n_items,
                      "calls_per_item": m["calls"] / n_items}
    return res


def contamination(agg: dict, models: list[str], k: int = 10, threshold: float = 0.2) -> dict:
    out = {}
    for model in models:
        for conf in ("L", "S+T+D"):
            key = f"{conf}@{model}"
            t = agg.get("test", {}).get(key, {}).get(f"recall@{k}")
            p = agg.get("post_cutoff", {}).get(key, {}).get(f"recall@{k}")
            if t is None or p is None:
                continue
            out[key] = {"test": t, "post_cutoff": p, "gap": t - p, "flag": (t - p) > threshold}
    return out


def run_eval(models: list[str] | None = None, paths: Paths | None = None) -> dict:
    paths = paths or Paths()
    cfg = load_eval_config()
    models = models if models is not None else model_ids()
    rows = collect_item_hits(cfg, models, paths)
    io.write_jsonl(paths.results / "item_hits.jsonl", rows)
    agg = aggregate(rows, cfg)
    result = {"models": models, "metrics": agg, "significance_vs_S": significance(rows),
              "triage": triage_quality(models, cfg, paths), "costs": costs(paths),
              "contamination": contamination(agg, models), "eval_config": cfg.model_dump()}
    io.write_json(paths.results / "metrics.json", result)
    return result
