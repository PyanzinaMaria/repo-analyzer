"""Unit tests for action parsing and quality detectors (no network)."""

from __future__ import annotations

import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from live_test_runner.actions import actions_in
from live_test_runner.detectors import ProblemReport, inspect_response
from live_test_runner.target.app import Booklet, render
from offline_sequence_benchmarks.genome import decode_action, encode_rank, random_genome
from random import Random


class ActionTests(unittest.TestCase):
    def test_home_links(self):
        html = render(Booklet())
        actions = actions_in(html)
        labels = [a.label for a in actions]
        self.assertIn("Text", labels)
        self.assertIn("Palette", labels)
        self.assertIn("Echo probe", labels)
        self.assertTrue(all(a.method == "GET" for a in actions))

    def test_form_actions(self):
        html = render(Booklet(page="/text"))
        actions = actions_in(html)
        posts = [a for a in actions if a.method == "POST"]
        self.assertEqual(len(posts), 3)
        self.assertEqual(posts[0].fields[0][0], "text")


class DetectorTests(unittest.TestCase):
    def test_counts_missing_headers_and_insecure_cookies(self):
        report = ProblemReport()
        inspect_response(
            report,
            status_code=200,
            headers={"set-cookie": "booklet=abc; Path=/"},
            body="<html>Echo: sandbox</html>",
            url="http://example/echo?q=sandbox",
            submitted_values=("sandbox",),
            page_path="/echo",
        )
        self.assertGreater(report.missing_security_headers, 0)
        self.assertGreater(report.insecure_cookies, 0)
        self.assertEqual(report.reflected_input, 1)
        self.assertGreater(report.problems_total, 0)
        self.assertIn("missing_security_headers|content-security-policy", report.findings)
        self.assertIn("insecure_cookies|missing_httponly", report.findings)
        self.assertIn("reflected_input|sandbox", report.findings)

    def test_dedup_keeps_unique_and_occurrences(self):
        report = ProblemReport()
        for page in ("/", "/text", "/"):
            inspect_response(
                report,
                status_code=200,
                headers={"set-cookie": "booklet=abc; Path=/"},
                body="ok",
                url=f"http://example{page}",
                page_path=page,
            )
        # 5 headers × 3 responses = 15 raw header hits; unique headers stay 5.
        self.assertEqual(report.missing_security_headers, 15)
        header_findings = [
            f for f in report.findings.values() if f.kind == "missing_security_headers"
        ]
        self.assertEqual(len(header_findings), 5)
        csp = report.findings["missing_security_headers|content-security-policy"]
        self.assertEqual(csp.occurrences, 3)
        self.assertEqual(csp.pages, {"/", "/text"})
        self.assertEqual(report.problems_unique, 5 + 3)  # 5 headers + 3 cookie flags
        payload = report.as_dict()
        self.assertEqual(payload["problems_unique"], report.problems_unique)
        self.assertEqual(len(payload["findings"]), report.problems_unique)

    def test_http_errors(self):
        report = ProblemReport()
        inspect_response(
            report, status_code=404, headers={}, body="x", url="/missing", page_path="/missing"
        )
        inspect_response(
            report, status_code=500, headers={}, body="x", url="/boom", page_path="/boom"
        )
        self.assertEqual(report.http_4xx, 1)
        self.assertEqual(report.http_5xx, 1)
        self.assertIn("http_4xx|404", report.findings)
        self.assertIn("http_5xx|500", report.findings)


class GenomeTests(unittest.TestCase):
    def test_decode_uses_offline_genome(self):
        actions = tuple(range(5))
        gene = encode_rank(3, 5)
        self.assertEqual(decode_action(gene, actions), 3)
        genome = random_genome(Random(1), 8)
        self.assertEqual(len(genome), 8)


if __name__ == "__main__":
    unittest.main()
