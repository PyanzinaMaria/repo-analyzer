import csv
import io
import json
import unittest
from collections import Counter
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

from offline_sequence_benchmarks import html_fixture, synthetic
from offline_sequence_benchmarks.__main__ import main


class FixtureTests(unittest.TestCase):
    def test_reference_graph_and_goal_depths(self):
        graph, rare = synthetic.build_graph(0)
        self.assertEqual(len(graph), 31)
        self.assertEqual(sorted(synthetic.shortest_distances(graph)[s] for s in rare),
                         [6, 7, 8, 9])
        reference = html_fixture.fixture_reference()
        self.assertEqual((reference["states"], reference["transitions"]), (93, 273))
        self.assertEqual(sorted(reference["proof_min_steps"].values()), [8, 11, 11])

    def test_new_action_at_existing_url(self):
        trial = html_fixture.HTMLTrial(10)
        self.assertEqual((len(trial.nodes), len(trial.edges)), (1, 0))
        plain = trial.observe(html_fixture.Booklet(page="/preview"))
        configured = trial.observe(html_fixture.Booklet(page="/preview", text="draft",
                                                        palette="green"))
        self.assertNotEqual(plain, configured)
        self.assertEqual(len(trial.actions(plain)), 1)
        self.assertEqual(len(trial.actions(configured)), 2)


class RunnerTests(unittest.TestCase):
    def test_smoke_budget_and_outputs(self):
        with TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()):
            main(["--profile", "smoke", "--output-dir", tmp])
            out = Path(tmp) / "smoke"
            self.assertEqual(len(list(out.iterdir())), 7)
            checks = [
                ("sequence_search_results.csv", "steps", 6),
                ("html_sequence_results.csv", "step", 6),
                ("html_tuning_test.csv", "step", 15),
                ("html_tuning_hybrids.csv", "step", 18),
            ]
            for filename, budget_column, count in checks:
                with self.subTest(file=filename):
                    with (out / filename).open(encoding="utf-8", newline="") as source:
                        rows = list(csv.DictReader(source))
                    self.assertEqual(len(rows), count)
                    self.assertTrue(all(row[budget_column] == "96" for row in rows))
            with (out / "html_tuning_dev.csv").open(encoding="utf-8", newline="") as source:
                self.assertEqual(Counter(r["method"] for r in csv.DictReader(source)),
                                 {"Q-tuned": 3, "GA-tuned": 3})
            summary = json.loads((out / "html_tuning_summary.json").read_text(encoding="utf-8"))
            keys = ("dev_seeds", "test_seeds", "hybrid_seeds")
            self.assertEqual(len(set().union(*(set(summary[key]) for key in keys))), 9)
            self.assertTrue({"Random+Q", "Random+GA", "Q+GA"} <= summary["hybrids"].keys())


if __name__ == "__main__":
    unittest.main()
