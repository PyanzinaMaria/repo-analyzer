"""Orchestrate live exploration: build graph, search, replay, emit metrics."""

from __future__ import annotations

import json
from pathlib import Path
from random import Random
from typing import Any

from .detectors import merge_findings, unique_problem_count
from .graph_trial import LiveTrial
from .http_client import LiveClient
from .search import METHODS, run_method


PROFILES = {
    "smoke": {"budget": 48, "horizon": 8, "seeds": 1, "methods": METHODS},
    "full": {"budget": 200, "horizon": 24, "seeds": 3, "methods": METHODS},
}


def _best_sequences(trial: LiveTrial) -> list[dict[str, Any]]:
    sequences = []
    for node, path in trial.examples.items():
        page = trial._page_of.get(node, "")
        if page.lstrip("/") in ("text-proof", "screen-proof", "print-proof"):
            labels = []
            state = "hub"
            # Replay labels from stored action indices when possible.
            for action_id in path:
                actions = trial.action_list(state) if state in trial.nodes else ()
                if action_id < len(actions):
                    labels.append(actions[action_id].describe())
                    # Prefer edge lookup for next state.
                    nxt = next(
                        (
                            target
                            for (src, act, target) in trial.edges
                            if src == state and act == action_id
                        ),
                        None,
                    )
                    if nxt is None:
                        break
                    state = nxt
                else:
                    labels.append(f"action#{action_id}")
                    break
            sequences.append(
                {
                    "page": page,
                    "node": node,
                    "length": len(path),
                    "actions": labels,
                }
            )
    return sequences


def run_once(
    client: LiveClient,
    *,
    method: str,
    seed: int,
    budget: int,
    horizon: int,
) -> dict[str, Any]:
    trial = LiveTrial(client, budget=budget, horizon=horizon)
    rng = Random(seed)
    run_method(trial, method, rng)
    if trial.steps < trial.budget:
        # Exhaust remaining budget with random walk so comparisons stay fair.
        from .search import online_search

        online_search(trial, rng, learning=False)
    assert trial.steps == trial.budget, (trial.steps, trial.budget)
    metrics = trial.metrics()
    return {
        "method": method,
        "seed": seed,
        "budget": budget,
        "horizon": horizon,
        **metrics,
        "best_sequences": _best_sequences(trial),
        "graph": trial.export_graph(),
    }


def run_pipeline(
    base_url: str,
    *,
    profile: str = "smoke",
    output_dir: Path | None = None,
    budget: int | None = None,
    horizon: int | None = None,
    start_path: str = "/",
) -> dict[str, Any]:
    if profile not in PROFILES:
        raise ValueError(f"Unknown profile: {profile}")
    cfg = dict(PROFILES[profile])
    if budget is not None:
        cfg["budget"] = budget
    if horizon is not None:
        cfg["horizon"] = horizon
    cfg["start_path"] = start_path

    output = Path(output_dir or Path(__file__).resolve().parent / "output" / profile)
    output.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, Any]] = []
    with LiveClient(base_url, start_path=start_path) as client:
        client.wait_ready()
        for seed in range(cfg["seeds"]):
            for method in cfg["methods"]:
                print(
                    f"Running {method} seed={seed} budget={cfg['budget']} "
                    f"horizon={cfg['horizon']}",
                    flush=True,
                )
                results.append(
                    run_once(
                        client,
                        method=method,
                        seed=seed + 1000,
                        budget=cfg["budget"],
                        horizon=cfg["horizon"],
                    )
                )

    global_findings = merge_findings([r.get("findings") or [] for r in results])
    problems_unique = unique_problem_count(global_findings)

    # Aggregate across runs.
    totals = {
        "states": max(r["states"] for r in results),
        "transitions": max(r["transitions"] for r in results),
        "proofs": max(r["proofs"] for r in results),
        "http_4xx": sum(r["http_4xx"] for r in results),
        "http_5xx": sum(r["http_5xx"] for r in results),
        "missing_security_headers": sum(r["missing_security_headers"] for r in results),
        "insecure_cookies": sum(r["insecure_cookies"] for r in results),
        "reflected_input": sum(r["reflected_input"] for r in results),
        "proof_reached": sum(r["proof_reached"] for r in results),
        "problems_total": sum(r["problems_total"] for r in results),
        "problems_unique": problems_unique,
    }
    by_method = {}
    for method in cfg["methods"]:
        group = [r for r in results if r["method"] == method]
        method_findings = merge_findings([r.get("findings") or [] for r in group])
        by_method[method] = {
            "runs": len(group),
            "avg_states": sum(r["states"] for r in group) / len(group),
            "avg_transitions": sum(r["transitions"] for r in group) / len(group),
            "avg_proofs": sum(r["proofs"] for r in group) / len(group),
            "problems_total": sum(r["problems_total"] for r in group),
            "problems_unique": unique_problem_count(method_findings),
            "best_proofs": max(r["proofs"] for r in group),
            "findings": method_findings,
        }

    report = {
        "profile": profile,
        "base_url": base_url,
        "config": cfg,
        "aggregates": totals,
        "findings": global_findings,
        "by_method": by_method,
        "runs": [
            {k: v for k, v in r.items() if k != "graph"}
            for r in results
        ],
        "graphs": {f"{r['method']}-seed{r['seed']}": r["graph"] for r in results},
    }

    metrics_path = output / "metrics.json"
    metrics_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {metrics_path}", flush=True)
    print(
        f"problems_total={totals['problems_total']} "
        f"problems_unique={totals['problems_unique']}",
        flush=True,
    )
    print(
        f"coverage: states={totals['states']} transitions={totals['transitions']} "
        f"proofs={totals['proofs']}",
        flush=True,
    )
    return report
