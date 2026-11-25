"""Optuna hyperparameter search for Q-learning and GA on the offline booklet.

Maximizes unique paths and findings (proof pages on the booklet stand).
Does NOT optimize against Random. Writes live_test_runner/hyperparams.json.

  python -m live_test_runner.optuna_tune --trials 40
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
from pathlib import Path
from random import Random
from statistics import mean

import optuna
from optuna.samplers import TPESampler

from offline_sequence_benchmarks.html_fixture import HTMLTrial, PROOFS

from .search import (
    GAConfig,
    HYPERPARAMS_PATH,
    QConfig,
    run_ga,
    run_q,
    run_random,
    save_hyperparams,
)

# Weight for rare booklet "findings" (proof pages) vs path coverage.
FINDINGS_WEIGHT = 20.0
# Weight for static Bandit findings in the combined experiment score.
CODE_VULN_WEIGHT = 1.0


def _metrics(seed: int, budget: int, horizon: int, method: str, cfg) -> dict:
    trial = HTMLTrial(budget, horizon)
    rng = Random(seed)
    if method == "Q":
        run_q(trial, rng, cfg)
    elif method == "GA":
        run_ga(trial, rng, cfg)
    else:
        run_random(trial, rng)
    assert trial.steps == budget

    # Unique paths: first discovered route to each non-start state.
    unique_paths = len(trial.examples)
    unique_transitions = len(trial.edges)
    # On the offline booklet, proof pages are the analogue of "findings".
    findings = sum(
        1
        for book, _, _ in trial.nodes.values()
        if book.page.lstrip("/") in PROOFS
    )
    return {
        "unique_paths": unique_paths,
        "unique_transitions": unique_transitions,
        "findings": findings,
        "states": len(trial.nodes),
    }


def objective_score(row: dict, *, code_vulnerabilities: int = 0) -> float:
    """Optuna/experiment score: paths + transitions + dynamic findings + code vulns.

    ``code_vulnerabilities`` comes from Bandit on the target source tree. It is
    the same for every trial of a given source, so it does not change Q vs GA
    ranking, but is part of the reported experiment metric.
    """
    return (
        float(row["unique_paths"])
        + float(row["unique_transitions"])
        + FINDINGS_WEIGHT * float(row["findings"])
        + CODE_VULN_WEIGHT * float(code_vulnerabilities)
    )


def _mean_metrics(
    method: str,
    cfg,
    seeds,
    budget: int,
    horizon: int,
    *,
    code_vulnerabilities: int = 0,
) -> dict:
    rows = [_metrics(seed, budget, horizon, method, cfg) for seed in seeds]
    return {
        "unique_paths": mean(r["unique_paths"] for r in rows),
        "unique_transitions": mean(r["unique_transitions"] for r in rows),
        "findings": mean(r["findings"] for r in rows),
        "code_vulnerabilities": code_vulnerabilities,
        "states": mean(r["states"] for r in rows),
        "score": mean(
            objective_score(r, code_vulnerabilities=code_vulnerabilities)
            for r in rows
        ),
    }


def _suggest_q(trial: optuna.Trial) -> QConfig:
    return QConfig(
        alpha=trial.suggest_float("q_alpha", 0.15, 0.9),
        gamma=trial.suggest_float("q_gamma", 0.4, 0.99),
        epsilon=trial.suggest_float("q_epsilon", 0.02, 0.45),
        bonus=trial.suggest_float("q_bonus", 0.0, 6.0),
        power=trial.suggest_float("q_power", 0.35, 1.25),
        use_time=trial.suggest_categorical("q_use_time", [False, True]),
    )


def _suggest_ga(trial: optuna.Trial) -> GAConfig:
    return GAConfig(
        population=trial.suggest_int("ga_population", 8, 28, step=2),
        mutation=trial.suggest_float("ga_mutation", 0.03, 0.35),
        immigrants=trial.suggest_float("ga_immigrants", 0.0, 0.4),
        tournament=trial.suggest_int("ga_tournament", 2, 5),
        scoring=trial.suggest_categorical(
            "ga_scoring", ["sum", "scaled-sum", "peak3"]
        ),
        power=trial.suggest_float("ga_power", 0.35, 1.25),
    )


def tune(
    *,
    trials: int = 40,
    budget: int = 240,
    horizon: int = 24,
    seeds: tuple[int, ...] = (0, 1, 2, 3, 4),
    output: Path | None = None,
    source_dir: Path | None = None,
) -> dict:
    from .code_scan import scan_code_vulnerabilities
    from .pipeline import DEFAULT_SOURCE_DIR

    optuna.logging.set_verbosity(optuna.logging.WARNING)
    code_root = Path(source_dir) if source_dir is not None else DEFAULT_SOURCE_DIR
    code_report = scan_code_vulnerabilities(code_root)
    code_vulns = int(code_report.get("code_vulnerabilities") or 0)
    print(
        f"Optuna objective: unique_paths + unique_transitions + "
        f"{FINDINGS_WEIGHT}*findings + {CODE_VULN_WEIGHT}*code_vulnerabilities "
        f"(code_vulnerabilities={code_vulns} from {code_root}) "
        f"(budget={budget}, horizon={horizon}, seeds={list(seeds)})",
        flush=True,
    )

    def q_objective(trial: optuna.Trial) -> float:
        cfg = _suggest_q(trial)
        return _mean_metrics(
            "Q", cfg, seeds, budget, horizon, code_vulnerabilities=code_vulns
        )["score"]

    def ga_objective(trial: optuna.Trial) -> float:
        cfg = _suggest_ga(trial)
        return _mean_metrics(
            "GA", cfg, seeds, budget, horizon, code_vulnerabilities=code_vulns
        )["score"]

    sampler = TPESampler(seed=42)
    q_study = optuna.create_study(direction="maximize", sampler=sampler, study_name="q")
    q_study.optimize(q_objective, n_trials=trials, show_progress_bar=False)
    ga_study = optuna.create_study(direction="maximize", sampler=sampler, study_name="ga")
    ga_study.optimize(ga_objective, n_trials=trials, show_progress_bar=False)

    qp = q_study.best_params
    gp = ga_study.best_params
    best_q = QConfig(
        alpha=qp["q_alpha"],
        gamma=qp["q_gamma"],
        epsilon=qp["q_epsilon"],
        bonus=qp["q_bonus"],
        power=qp["q_power"],
        use_time=qp["q_use_time"],
    )
    best_ga = GAConfig(
        population=gp["ga_population"],
        mutation=gp["ga_mutation"],
        immigrants=gp["ga_immigrants"],
        tournament=gp["ga_tournament"],
        scoring=gp["ga_scoring"],
        power=gp["ga_power"],
    )

    holdout = tuple(range(100, 108))
    q_hold = _mean_metrics(
        "Q", best_q, holdout, budget, horizon, code_vulnerabilities=code_vulns
    )
    ga_hold = _mean_metrics(
        "GA", best_ga, holdout, budget, horizon, code_vulnerabilities=code_vulns
    )
    # Random is reported for context only — not used as the Optuna target.
    random_hold = _mean_metrics(
        "R", None, holdout, budget, horizon, code_vulnerabilities=code_vulns
    )

    meta = {
        "objective": (
            "unique_paths + unique_transitions + "
            f"{FINDINGS_WEIGHT}*findings + "
            f"{CODE_VULN_WEIGHT}*code_vulnerabilities"
        ),
        "findings_meaning": (
            "On the offline booklet, findings = number of proof pages reached "
            "(text/screen/print-proof). Live runs use problems_unique/detectors."
        ),
        "code_vulnerabilities_meaning": (
            "Bandit SAST count on --source-dir / TARGET_SOURCE_DIR "
            "(default: live_test_runner/target)."
        ),
        "code_vulnerabilities_report": code_report,
        "optuna_trials": trials,
        "budget": budget,
        "horizon": horizon,
        "train_seeds": list(seeds),
        "holdout_seeds": list(holdout),
        "q_best_train_score": q_study.best_value,
        "ga_best_train_score": ga_study.best_value,
        "holdout": {
            "q": q_hold,
            "ga": ga_hold,
            "random_context_only": random_hold,
        },
    }
    path = save_hyperparams(best_q, best_ga, output or HYPERPARAMS_PATH, meta=meta)
    print(f"Saved {path}", flush=True)
    print(f"Q config: {asdict(best_q)}", flush=True)
    print(f"GA config: {asdict(best_ga)}", flush=True)
    print(
        f"Hold-out Q: paths={q_hold['unique_paths']:.2f} "
        f"transitions={q_hold['unique_transitions']:.2f} "
        f"findings={q_hold['findings']:.2f} "
        f"code_vulnerabilities={code_vulns} score={q_hold['score']:.2f}",
        flush=True,
    )
    print(
        f"Hold-out GA: paths={ga_hold['unique_paths']:.2f} "
        f"transitions={ga_hold['unique_transitions']:.2f} "
        f"findings={ga_hold['findings']:.2f} "
        f"code_vulnerabilities={code_vulns} score={ga_hold['score']:.2f}",
        flush=True,
    )
    return {"q": asdict(best_q), "ga": asdict(best_ga), "meta": meta, "path": str(path)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=40)
    parser.add_argument("--budget", type=int, default=240)
    parser.add_argument("--horizon", type=int, default=24)
    parser.add_argument("--seeds", type=int, default=5, help="Train seed count starting at 0")
    parser.add_argument("--output", type=Path, default=HYPERPARAMS_PATH)
    parser.add_argument(
        "--source-dir",
        type=Path,
        default=None,
        help="Source tree for Bandit code_vulnerabilities metric",
    )
    args = parser.parse_args(argv)
    if min(args.trials, args.budget, args.horizon, args.seeds) < 1:
        parser.error("trials/budget/horizon/seeds must be positive")
    tune(
        trials=args.trials,
        budget=args.budget,
        horizon=args.horizon,
        seeds=tuple(range(args.seeds)),
        output=args.output,
        source_dir=args.source_dir,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
