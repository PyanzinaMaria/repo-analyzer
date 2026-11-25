"""Tests for Bandit-backed code vulnerability metric."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from live_test_runner.code_scan import scan_code_vulnerabilities


class CodeScanTests(unittest.TestCase):
    def test_missing_source(self):
        report = scan_code_vulnerabilities(ROOT / "no_such_source_dir_xyz")
        self.assertEqual(report["status"], "missing_source")
        self.assertEqual(report["code_vulnerabilities"], 0)

    def test_scans_booklet_target(self):
        target = ROOT / "live_test_runner" / "target"
        report = scan_code_vulnerabilities(target)
        self.assertIn(report["status"], {"ok", "bandit_not_installed"})
        self.assertIn("code_vulnerabilities", report)
        self.assertIsInstance(report["code_vulnerabilities"], int)
        self.assertGreaterEqual(report["code_vulnerabilities"], 0)


if __name__ == "__main__":
    unittest.main()
