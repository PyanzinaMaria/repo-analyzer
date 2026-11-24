"""Integration smoke: start booklet server in-process and run a tiny pipeline."""

from __future__ import annotations

import sys
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from live_test_runner.http_client import LiveClient
from live_test_runner.pipeline import run_once
from live_test_runner.target.app import Handler


class LiveSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_random_run_emits_metrics(self):
        with LiveClient(self.base_url) as client:
            client.wait_ready(attempts=20)
            result = run_once(
                client, method="Random", seed=1, budget=16, horizon=4
            )
        self.assertEqual(result["steps"], 16)
        self.assertGreaterEqual(result["states"], 1)
        self.assertIn("problems_total", result)
        self.assertIn("problems_unique", result)
        self.assertGreater(result["problems_total"], 0)
        self.assertGreater(result["problems_unique"], 0)
        self.assertLess(result["problems_unique"], result["problems_total"])
        self.assertGreater(result["missing_security_headers"], 0)
        self.assertTrue(result["findings"])
        fingerprints = {item["fingerprint"] for item in result["findings"]}
        self.assertIn("missing_security_headers|content-security-policy", fingerprints)

    def test_q_and_genetic_run(self):
        with LiveClient(self.base_url) as client:
            client.wait_ready(attempts=20)
            q = run_once(client, method="Q-learning", seed=2, budget=12, horizon=4)
            g = run_once(client, method="Genetic", seed=3, budget=12, horizon=4)
        self.assertEqual(q["steps"], 12)
        self.assertEqual(g["steps"], 12)
        self.assertGreaterEqual(q["transitions"] + g["transitions"], 1)


if __name__ == "__main__":
    unittest.main()
