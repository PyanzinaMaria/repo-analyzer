"""Offline checks of the SAST benchmark scoring path: per-tool rankings, coverage stats,
paired comparison, and the checked-in pilot fixture. No scanners or network involved."""

from __future__ import annotations

import json
from pathlib import Path

from app.core import io
from app.sast.normalize import Finding, merge
from bench.config import Paths
from bench.eval.metrics import paired_tools, scan_coverage
from bench.rank import build_rankings
from bench.schemas import BenchmarkItem

FIXTURE = Path(__file__).parent / "fixtures" / "sast-pilot"


def _finding(tool: str, line: int, item: str = "it", side: str = "vuln") -> Finding:
    return Finding(id=f"{item}-{side}-{tool}-{line}", item_id=item, side=side, tool=tool,
                   rule_id="weak-digest", cwe=["CWE-328"], severity="warning", file="src/digest.py",
                   start_line=line, end_line=line, message="MD5 is unsuitable for integrity protection.")


def _write_scan(paths: Paths, item: str, side: str, findings: list[Finding], statuses: list[dict]) -> None:
    d = paths.sast / item / side
    d.mkdir(parents=True)
    io.write_jsonl(d / "findings.jsonl", [json.loads(f.model_dump_json()) for f in findings])
    io.write_jsonl(d / "merged.jsonl",
                   [json.loads(m.model_dump_json()) for m in merge(findings, 3)])
    io.write_json(d / "runs.json", {"tools": {s["tool"]: s for s in statuses}, "merge_line_tol": 3})


def test_per_tool_rankings_keep_empty_ok_runs(tmp_path):
    paths = Paths(root=tmp_path)
    hits = _finding("a", 7)
    _write_scan(paths, "it", "vuln", [hits],
                [{"tool": "a", "ok": True}, {"tool": "b", "ok": True}])
    ranks = build_rankings("it", "vuln", [], paths)
    # A successful zero-finding run must still contribute its own ranking (empty list, not a missing key).
    assert set(ranks) == {"S", "S-a", "S-b"}
    assert ranks["S-a"][0]["start_line"] == 7
    assert ranks["S-b"] == []


def test_failed_tool_gets_no_ranking(tmp_path):
    paths = Paths(root=tmp_path)
    _write_scan(paths, "it", "vuln", [_finding("a", 7)],
                [{"tool": "a", "ok": True}, {"tool": "b", "ok": False, "reason": "timeout"}])
    ranks = build_rankings("it", "vuln", [], paths)
    assert set(ranks) == {"S", "S-a"}


def test_scan_coverage_counts_statuses(tmp_path):
    paths = Paths(root=tmp_path)
    (paths.benchmark).write_text(
        json.dumps({"id": "x", "split": "dev", "language": "python", "gt_locations": [{"file": "a.py",
                    "kind": "sink", "start_line": 1, "end_line": 1}]}) + "\n", encoding="utf-8")
    _write_scan(paths, "x", "vuln", [_finding("a", 1)],
                [{"tool": "a", "ok": True}, {"tool": "b", "ok": False, "reason": "not_applicable"},
                 {"tool": "c", "ok": False, "reason": "timeout"}])
    coverage = scan_coverage(paths)
    counts = coverage["dev"]["a"]
    assert counts["ok"] == 1 and counts["applicable"] == 1
    assert coverage["dev"]["b"]["not_applicable"] == 1
    assert coverage["dev"]["c"]["timeout"] == 1 and coverage["dev"]["c"]["applicable"] == 1


def test_paired_tools_compares_only_common_items():
    rows = [{"split": "dev", "config": "S-a", "item": i, "func_rank": r}
            for i, r in (("x", 1), ("y", None), ("z", 2))]
    rows += [{"split": "dev", "config": "S-b", "item": i, "func_rank": r}
             for i, r in (("x", None), ("y", 1))]
    (cmp,) = paired_tools(rows, k=10)
    # "z" has no S-b observation, so the comparison is restricted to the common pair {x, y}.
    assert (cmp["a"], cmp["b"], cmp["n"], cmp["hits_a"], cmp["hits_b"]) == ("S-a", "S-b", 2, 1, 1)


def test_pilot_fixture_is_valid_and_labels_hold():
    items = [BenchmarkItem.model_validate(json.loads(line))
             for line in (FIXTURE / "benchmark.jsonl").read_text(encoding="utf-8").splitlines()]
    assert {it.language for it in items} >= {"java", "csharp"}
    for it in items:
        for gt in it.gt_locations:
            vuln = (FIXTURE / "snapshots" / it.id / "vuln" / gt.file).read_text(encoding="utf-8").splitlines()
            fixed = (FIXTURE / "snapshots" / it.id / "fixed" / gt.fixed_file).read_text(encoding="utf-8").splitlines()
            assert gt.start_line <= len(vuln) and gt.fixed_start_line <= len(fixed)
            assert vuln[gt.start_line - 1] != fixed[gt.fixed_start_line - 1]
