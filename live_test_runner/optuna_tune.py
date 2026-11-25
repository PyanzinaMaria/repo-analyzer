"""Optuna hyperparameter search for Q-learning and GA.

Maximizes ``problems_unique`` (deduplicated dynamic detector findings) on the
live booklet HTTP stand. Writes live_test_runner/hyperparams.json.

  python -m live_test_runner.optuna_tune --trials 24
"""

from __future__ import annotations

import argparse
import threading
from dataclasses import asdict
from http.server import ThreadingHTTPServer
from pathlib import Path
from random import Random
from statistics import mean

import optuna
from optuna.samplers import TPESampler

from .graph_trial import LiveTrial
from .http_client import LiveClient
from .search import (
    GAConfig,
    HYPERPARAMS_PATH,
    QConfig,
    run_ga,
    run_q,
    run_random,
    save_hyperparams,
)
from .target.app import Handler


class _BookletServer:
    """In-process booklet target shared across Optuna trials."""

    def __init__(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def _live_metrics(
    base_url: str,
    seed: int,
    budget: int,
    horizon: int,
    method: str,
    cfg,
) -> dict:
    with LiveClient(base_url, timeout=5.0) as client:
        client.wait_ready(attempts=20)
        trial = LiveTrial(client, budget=budget, horizon=horizon)
        rng = Random(seed)
        if method == "Q":
            run_q(trial, rng, cfg)
        elif method == "GA":
            run_ga(trial, rng, cfg)
        else:
            run_random(trial, rng)
        if trial.steps < trial.budget:
            run_random(trial, rng)
        assert trial.steps == trial.budget
        return {
            "problems_unique": trial.problems.problems_unique,
            "problems_total": trial.problems.problems_total,
            "states": len(trial.nodes),
            "transitions": len(trial.edges),
            "unique_paths": len(trial.examples),
        }


def _mean_metrics(
    base_url: str,
    method: str,
    cfg,
    seeds,
    budget: int,
    horizon: int,
) -> dict:
    rows = [
        _live_metrics(base_url, seed, budget, horizon, method, cfg)
        for seed in seeds
    ]
    return {
        "problems_unique": mean(r["problems_unique"] for r in rows),
        "problems_total": mean(r["problems_total"] for r in rows),
        "states": mean(r["states"] for r in rows),
        "transitions": mean(r["transitions"] for r in rows),
        "unique_paths": mean(r["unique_paths"] for r in rows),
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
    trials: int = 24,
    budget: int = 100,
    horizon: int = 20,
    seeds: tuple[int, ...] = (0, 1, 2),
    output: Path | None = None,
) -> dict:
    optuna.logging.set_verbosity(optuna.logging.WARNING)
    server = _BookletServer()
    server.start()
    print(
        f"Optuna objective: maximize problems_unique "
        f"(live booklet {server.base_url}; budget={budget}, horizon={horizon}, "
        f"seeds={list(seeds)}, trials={trials})",
        flush=True,
    )
    try:
        def q_objective(trial: optuna.Trial) -> float:
            cfg = _suggest_q(trial)
            metrics = _mean_metrics(
                server.base_url, "Q", cfg, seeds, budget, horizon
            )
            trial.set_user_attr("metrics", metrics)
            return float(metrics["problems_unique"])

        def ga_objective(trial: optuna.Trial) -> float:
            cfg = _suggest_ga(trial)
            metrics = _mean_metrics(
                server.base_url, "GA", cfg, seeds, budget, horizon
            )
            trial.set_user_attr("metrics", metrics)
            return float(metrics["problems_unique"])

        sampler = TPESampler(seed=42)
        q_study = optuna.create_study(
            direction="maximize", sampler=sampler, study_name="q-problems-unique"
        )
        q_study.optimize(q_objective, n_trials=trials, show_progress_bar=False)
        ga_study = optuna.create_study(
            direction="maximize", sampler=sampler, study_name="ga-problems-unique"
        )
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

        holdout = tuple(range(100, 105))
        q_hold = _mean_metrics(
            server.base_url, "Q", best_q, holdout, budget, horizon
        )
        ga_hold = _mean_metrics(
            server.base_url, "GA", best_ga, holdout, budget, horizon
        )
        random_hold = _mean_metrics(
            server.base_url, "R", None, holdout, budget, horizon
        )

        meta = {
            "objective": "maximize problems_unique",
            "target": "live booklet HTTP stand",
            "optuna_trials": trials,
            "budget": budget,
            "horizon": horizon,
            "train_seeds": list(seeds),
            "holdout_seeds": list(holdout),
            "q_best_train_problems_unique": q_study.best_value,
            "ga_best_train_problems_unique": ga_study.best_value,
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
            f"Hold-out problems_unique: "
            f"Q={q_hold['problems_unique']:.2f} "
            f"GA={ga_hold['problems_unique']:.2f} "
            f"Random={random_hold['problems_unique']:.2f}",
            flush=True,
        )
        return {
            "q": asdict(best_q),
            "ga": asdict(best_ga),
            "meta": meta,
            "path": str(path),
        }
    finally:
        server.stop()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=24)
    parser.add_argument("--budget", type=int, default=100)
    parser.add_argument("--horizon", type=int, default=20)
    parser.add_argument("--seeds", type=int, default=3, help="Train seed count from 0")
    parser.add_argument("--output", type=Path, default=HYPERPARAMS_PATH)
    args = parser.parse_args(argv)
    if min(args.trials, args.budget, args.horizon, args.seeds) < 1:
        parser.error("trials/budget/horizon/seeds must be positive")
    tune(
        trials=args.trials,
        budget=args.budget,
        horizon=args.horizon,
        seeds=tuple(range(args.seeds)),
        output=args.output,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
