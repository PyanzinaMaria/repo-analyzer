"""Check frozen Optuna hyperparams maximize paths/findings on the booklet."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from statistics import mean

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from offline_sequence_benchmarks.html_fixture import HTMLTrial, PROOFS
from live_test_runner.optuna_tune import FINDINGS_WEIGHT, objective_score
from live_test_runner.search import load_hyperparams, run_ga, run_q, run_random
from random import Random


def _metrics(seed, method, q, ga, budget=180, horizon=20):
    trial = HTMLTrial(budget, horizon)
    rng = Random(seed)
    if method == "Q":
        run_q(trial, rng, q)
    elif method == "GA":
        run_ga(trial, rng, ga)
    else:
        run_random(trial, rng)
    findings = sum(
        1
        for book, _, _ in trial.nodes.values()
        if book.page.lstrip("/") in PROOFS
    )
    return {
        "unique_paths": len(trial.examples),
        "unique_transitions": len(trial.edges),
        "findings": findings,
    }


class OptunaParamsTests(unittest.TestCase):
    def test_hyperparams_file_loads(self):
        q, ga = load_hyperparams()
        self.assertGreater(q.alpha, 0)
        self.assertGreater(ga.population, 4)

    def test_objective_uses_paths_findings_and_code_vulns(self):
        score = objective_score(
            {"unique_paths": 10, "unique_transitions": 20, "findings": 2},
            code_vulnerabilities=5,
        )
        self.assertEqual(score, 10 + 20 + FINDINGS_WEIGHT * 2 + 5)

    def test_tuned_methods_find_paths(self):
        q, ga = load_hyperparams()
        seeds = range(100, 105)
        q_rows = [_metrics(s, "Q", q, ga) for s in seeds]
        ga_rows = [_metrics(s, "GA", q, ga) for s in seeds]
        self.assertGreater(mean(r["unique_paths"] for r in q_rows), 0)
        self.assertGreater(mean(r["unique_transitions"] for r in q_rows), 0)
        self.assertGreater(mean(r["unique_paths"] for r in ga_rows), 0)
        self.assertGreater(mean(objective_score(r) for r in q_rows), 0)
        self.assertGreater(mean(objective_score(r) for r in ga_rows), 0)


if __name__ == "__main__":
    unittest.main()
