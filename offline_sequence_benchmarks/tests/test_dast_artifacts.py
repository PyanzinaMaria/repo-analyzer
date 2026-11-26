import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from offline_sequence_benchmarks import dast_artifacts as bridge, html_fixture


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.meta = {"runners": ["static", "dynamic"], "dast": {"status": "ok"}}

    def write_json(self, filename, data):
        path = self.root / filename
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_never_reads_unselected_unsuccessful_or_unknown_runs(self):
        with patch.object(bridge, "_read_json", side_effect=AssertionError("must not read")):
            for runners in ([], ["static"], ["ai"]):
                self.assertIsNone(bridge.summarize_artifacts(
                    {"runners": runners, "dast": {"status": "ok"}}, zap_report="stale.json"))
            self.assertIsNone(bridge.summarize_artifacts({}))
            for status, expected in (("failed", "failed"), ("skipped", "skipped"),
                                     ("running", "unknown"), (None, "unknown")):
                with self.subTest(status=status):
                    output = bridge.summarize_artifacts(
                        {"runners": ["dynamic"], "dast": {"status": status}},
                        zap_report="stale.json", coverage_trace="stale-trace.json")
                    self.assertEqual(output["dast_status"], expected)
                    self.assertEqual(output["coverage"], {"status": "not_read"})
                    self.assertEqual(output["zap"], {"status": "not_read"})

    def test_only_aggregates_are_returned(self):
        private_details = "do-not-print-test-session-secret"
        path = self.write_json("zap.json", {"site": [
            {"@name": private_details, "alerts": [
                {"riskcode": 3, "desc": private_details, "instances": [private_details] * 5},
                {"riskcode": "1"}, {"riskcode": "?"}]},
            {"alerts": [{"riskcode": "0"}, {"riskcode": "1"}]},
        ]})
        original_meta = json.dumps(self.meta)
        original_export = path.read_bytes()
        output = bridge.summarize_artifacts(self.meta, zap_report=path)
        self.assertEqual(output["dast_status"], "completed")
        self.assertEqual(output["zap"], {
            "status": "available", "sites": 2, "alert_groups": 5,
            "by_risk": {"informational": 1, "low": 2, "medium": 0, "high": 1, "unknown": 1},
        })
        self.assertNotIn(private_details, json.dumps(output))
        self.assertEqual(original_meta, json.dumps(self.meta))
        self.assertEqual(original_export, path.read_bytes())
        self.assertEqual(output["coverage"], {"status": "not_provided"})

    def test_empty_report_is_distinct_from_missing_or_invalid(self):
        self.meta["dast"]["status"] = "partial"
        zap = self.write_json("empty.json", {"site": [{"alerts": []}]})
        result = bridge.summarize_artifacts(self.meta, zap_report=zap,
                                            coverage_trace=self.root / "missing.json")
        self.assertEqual(result["dast_status"], "partial")
        self.assertEqual(result["zap"]["alert_groups"], 0)
        self.assertEqual(result["coverage"], {"status": "missing"})
        for value in ({}, {"site": [{}]}, {"site": [{"alerts": [{}]}]}):
            bad = self.write_json("bad.json", value)
            invalid = bridge.summarize_artifacts(self.meta, zap_report=bad)["zap"]
            self.assertEqual(invalid, {"status": "invalid"})
        with patch.object(bridge, "MAX_JSON_BYTES", 2):
            self.assertEqual(bridge.summarize_artifacts(self.meta, zap_report=zap)["zap"],
                             {"status": "invalid"})

    def test_coverage_matches_existing_fixture_and_accepts_longer_traces(self):
        class RecordedTrial(html_fixture.HTMLTrial):
            episodes = []
            ids = {}

            def step(self, state, action, path):
                if not path:
                    self.episodes.append([])
                target, reward = super().step(state, action, path)
                start_id = self.ids.setdefault(state, len(self.ids))
                target_id = self.ids.setdefault(target, len(self.ids))
                self.episodes[-1].append([start_id, action, target_id])
                return target, reward

        with patch.object(html_fixture, "HTMLTrial", RecordedTrial):
            row, _, _ = html_fixture.evaluate(17, "Random", 96)
        path = self.write_json("coverage.json", {
            "schema_version": 1, "episodes": RecordedTrial.episodes,
        })
        coverage = bridge.summarize_artifacts(self.meta, coverage_trace=path)["coverage"]
        self.assertEqual(coverage["steps"], row["step"])
        self.assertEqual(coverage["unique_transitions"], row["transitions"])
        self.assertEqual(coverage["observed_states"], row["states"])
        long_path = self.write_json("long.json", {"schema_version": 1, "episodes": [[[0, 2, 0]] * 128]})
        long_coverage = bridge.summarize_artifacts(self.meta, coverage_trace=long_path)["coverage"]
        self.assertEqual(long_coverage, {
            "status": "available", "steps": 128, "episodes": 1, "observed_states": 1,
            "unique_transitions": 1, "longest_episode": 128,
        })

    def test_invalid_trace_never_yields_partial_counts(self):
        examples = (
            [[[0, 0, 1], [2, 0, 3]]],
            [[[0, True, 1]]],
            [[[0, 0, -1]]],
            [[["private-data", 0, 1]]],
            [[]],
        )
        for episodes in examples:
            with self.subTest(episodes=episodes):
                path = self.write_json("invalid.json", {"schema_version": 1, "episodes": episodes})
                output = bridge.summarize_artifacts(self.meta, coverage_trace=path)
                self.assertEqual(output["coverage"], {"status": "invalid"})

    def test_graph_only_contains_observed_edges_and_preserves_distinct_outcomes(self):
        trace = {"schema_version": 1, "episodes": [
            [[0, 4, 1], [1, 5, 0]],
            [[0, 4, 2]],
            [[0, 4, 1]],
            [[3, 9, 3]],
        ], "extra": "not included in the graph"}
        graph = bridge.build_observed_graph(trace)
        self.assertEqual(graph["steps"], 5)
        self.assertEqual(graph["graph"], {
            "states": [0, 1, 2, 3],
            "start_states": [0, 3],
            "edges": [
                {"source": 0, "action": 4, "target": 1, "observations": 2},
                {"source": 0, "action": 4, "target": 2, "observations": 1},
                {"source": 1, "action": 5, "target": 0, "observations": 1},
                {"source": 3, "action": 9, "target": 3, "observations": 1},
            ],
        })
        self.assertNotIn("extra", json.dumps(graph))
        empty = bridge.build_observed_graph({"schema_version": 1, "episodes": []})
        self.assertEqual(empty["graph"], {"states": [], "start_states": [], "edges": []})

    def test_graph_cli_does_not_require_zap_or_dast_metadata(self):
        path = self.write_json("trace.json", {"schema_version": 1, "episodes": [[[0, 4, 1]]]})
        out = io.StringIO()
        with redirect_stdout(out):
            bridge.main(["--graph-from-trace", str(path)])
        self.assertEqual(json.loads(out.getvalue())["graph"]["states"], [0, 1])

        path.write_text('{"schema_version": 1, "episodes": [[[0, 4, 1], [3, 4, 0]]]}',
                        encoding="utf-8")
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            bridge.main(["--graph-from-trace", str(path)])
        self.assertEqual(error.exception.code, 2)

    def test_cli_json_and_bad_metadata(self):
        meta = self.write_json("meta.json", self.meta)
        out = io.StringIO()
        with redirect_stdout(out):
            bridge.main(["--meta", str(meta)])
        self.assertEqual(json.loads(out.getvalue())["dast_status"], "completed")
        invalid_meta = self.write_json("bad-meta.json", {"runners": "dynamic"})
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            bridge.main(["--meta", str(invalid_meta)])
        self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
