"""Check frozen Optuna hyperparams target problems_unique."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from live_test_runner.search import HYPERPARAMS_PATH, load_hyperparams


class OptunaParamsTests(unittest.TestCase):
    def test_hyperparams_file_loads(self):
        q, ga = load_hyperparams()
        self.assertGreater(q.alpha, 0)
        self.assertGreater(ga.population, 4)

    def test_objective_is_problems_unique(self):
        data = json.loads(HYPERPARAMS_PATH.read_text(encoding="utf-8"))
        meta = data.get("meta") or {}
        self.assertIn("problems_unique", str(meta.get("objective", "")))


if __name__ == "__main__":
    unittest.main()
