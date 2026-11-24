import csv
import io
import json
import unittest
from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from random import Random
from tempfile import TemporaryDirectory
from unittest.mock import patch

from offline_sequence_benchmarks import genome, html_fixture, synthetic, tuning
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


class VariableActionTests(unittest.TestCase):
    def test_rank_round_trip_and_unbounded_branching(self):
        for count in (1, 2, 3, 4, 7, 11, 101):
            actions = tuple(f"action-{i}" for i in range(count))
            for i, action in enumerate(actions):
                self.assertEqual(genome.decode_action(genome.encode_rank(i, count), actions),
                                 action)
        genes = genome.random_genome(Random(18), 1000)
        self.assertEqual({genome.decode_action(gene, range(11)) for gene in genes},
                         set(range(11)))
        self.assertEqual(genome.mutate(genes, Random(18), 0), genes)

    @staticmethod
    def render_variable(book):
        html = render_booklet(book)
        extra = ""
        if book.page == "/":
            extra = ('<a href="/text" aria-label="Extra text">Extra text</a>'
                     '<a href="/palette" aria-label="Extra palette">Extra palette</a>'
                     '<a href="/cover" aria-label="Extra cover">Extra cover</a>')
        elif book.page == "/cover":
            extra = '<a href="/text" aria-label="Continue to text">Continue to text</a>'
        return html.replace("</body>", extra + "</body>")

    def test_warm_start_preserves_indices_as_counts_change(self):
        with patch.object(html_fixture, "render", self.render_variable):
            trial = html_fixture.HTMLTrial(10)
            start = synthetic.START
            intermediate, _ = trial.step(start, 6, ())
            end, _ = trial.step(intermediate, 2, (6,))
            self.assertEqual((len(trial.actions(start)), len(trial.actions(intermediate))),
                             (7, 3))
            targets = {(s, a): nxt for s, a, nxt in trial.edges}
            genes = tuning.encode_observed_prefix(trial, trial.examples[end], targets)
            state, actions = start, []
            for gene in genes:
                action = genome.decode_action(gene, trial.actions(state))
                state = targets[state, action]
                actions.append(action)
            self.assertEqual((actions, state, trial.steps), ([6, 2], end, 2))

    def test_original_tuned_and_hybrid_run_with_variable_actions(self):
        config = tuning.GAConfig(6, 0.28, 0.36, 2, "sum", 1.0)
        q_config = tuning.QConfig(0.85, 0.4, 0.45, 2.0, 1.0, False)
        with patch.object(html_fixture, "render", self.render_variable):
            for method in ("GA-original", "GA-tuned", "Random+GA", "Q+GA"):
                with self.subTest(method=method):
                    row = tuning.trial_row(17, 600, method, config,
                                           q=q_config, ga=config)
                    self.assertEqual(row["step"], 600)
            _, trial, _ = html_fixture.evaluate(17, "Genetic", 600)
            self.assertIn(6, {a for s, a, _ in trial.edges if s == synthetic.START})


render_booklet = html_fixture.render


class EpisodeLimitTests(unittest.TestCase):
    def test_all_policies_can_exceed_previous_limit(self):
        class RecordingTrial(synthetic.Trial):
            def step(self, state, action, path):
                self.episode_positions.append(len(path) + 1)
                return super().step(state, action, path)

        q = tuning.QConfig(0.85, 0.4, 0.45, 2.0, 1.0, False)
        ga = tuning.GAConfig(6, 0.28, 0.36, 2, "sum", 1.0)
        policies = (
            lambda trial, rng: synthetic.online_search(trial, rng, learning=False),
            lambda trial, rng: synthetic.online_search(trial, rng, learning=True),
            synthetic.genetic_search,
            lambda trial, rng: tuning.run_q(trial, rng, q),
            lambda trial, rng: tuning.run_ga(trial, rng, ga),
            lambda trial, rng: tuning.run_random_prefix(trial, rng, trial.budget),
        )
        self.assertEqual(synthetic.HORIZON, 64)
        self.assertEqual(html_fixture.HTMLTrial(1).horizon, 64)
        for horizon in (64, 128):
            for index, policy in enumerate(policies):
                with self.subTest(horizon=horizon, policy=index):
                    start = synthetic.START
                    trial = RecordingTrial({start: (start,)}, horizon + 1, horizon=horizon)
                    trial.episode_positions = []
                    policy(trial, Random(1))
                    self.assertEqual(trial.episode_positions, [*range(1, horizon + 1), 1])
                    self.assertEqual(trial.steps, horizon + 1)

    def test_nonpositive_limits_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "horizon"):
            synthetic.Trial({}, 1, horizon=0)
        with self.assertRaisesRegex(ValueError, "horizon"):
            html_fixture.HTMLTrial(1, horizon=0)
        for entry in (main, synthetic.main, html_fixture.main, tuning.main):
            with self.subTest(entry=entry.__module__):
                errors = io.StringIO()
                with redirect_stderr(errors), self.assertRaises(SystemExit) as error:
                    entry(["--horizon", "0"])
                self.assertEqual(error.exception.code, 2)
                self.assertIn("horizon", errors.getvalue())


class RunnerTests(unittest.TestCase):
    def test_smoke_with_one_action_episodes(self):
        with TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()):
            main(["--horizon", "1", "--output-dir", tmp])
            with (Path(tmp) / "smoke" / "html_tuning_hybrids.csv").open(
                    encoding="utf-8", newline="") as source:
                rows = list(csv.DictReader(source))
            self.assertEqual(len(rows), 18)
            self.assertTrue(all(row["step"] == "96" and row["transitions"] == "4" for row in rows))

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
