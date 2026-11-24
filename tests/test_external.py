"""Offline checks of the external benchmark adapters (OWASP CSV parsing, SecLens task mapping,
RealVuln ground-truth filtering, scan attribution). No network, no clones."""

from __future__ import annotations

from bench.external import SUPPORTED, _copy_scan, _owasp_categories, _realvuln_gt, _seclens_item


def test_owasp_categories_skip_header_and_false_rows():
    lines = [
        "# test name, category, real vulnerability, cwe, Benchmark version: 1.2, 2016-06-1",
        "BenchmarkTest00001,pathtraver,true,22",
        "BenchmarkTest00002,pathtraver,true,22",
        "BenchmarkTest00003,hash,true,328",
        "BenchmarkTest00004,pathtraver,false,22",
        "Broken,row",
    ]
    cats = _owasp_categories(lines)
    assert cats == {("pathtraver", "CWE-22"): ["BenchmarkTest00001", "BenchmarkTest00002"],
                    ("hash", "CWE-328"): ["BenchmarkTest00003"]}


def _seclens_task(iid, task_type="true_positive", language="Python", paired_with=None):
    t = {
        "id": iid, "version": "1", "type": task_type,
        "repository": {"url": "https://github.com/x/y", "commit": f"{'a' * 40 if task_type == 'true_positive' else 'b' * 40}",
                       "language": language},
        "target": {"function": "f", "file": "app.py", "line_start": 3, "line_end": 7},
        "ground_truth": {"vulnerable": task_type == "true_positive", "cwe": "CWE-89", "severity": "high",
                         "category": "Injection", "location": None},
        "metadata": {"cve_id": "CVE-1", "paired_with": paired_with},
    }
    return t


def test_seclens_task_maps_pair_and_unsupported_language():
    pos = _seclens_task("t1", paired_with="t2")
    post = _seclens_task("t2", task_type="post_patch")
    it = _seclens_item(pos, {"t1": pos, "t2": post})
    assert it is not None
    assert it.fix_commit == "b" * 40 and it.fix_commit != it.vuln_commit
    gt = it.gt_locations[0]
    assert (gt.file, gt.start_line, gt.end_line) == ("app.py", 3, 7)
    assert (gt.fixed_file, gt.fixed_start_line) == ("app.py", 3)

    assert _seclens_item(_seclens_task("t3", language="Go"), {"t3": None}) is None
    assert _seclens_item(_seclens_task("t4", task_type="post_patch"), {"t4": None}) is None
    assert "python" in SUPPORTED and "c#" in SUPPORTED


def test_realvuln_gt_filters_by_cwe_and_traps():
    data = {"findings": [
        {"is_vulnerable": True, "primary_cwe": "CWE-89", "acceptable_cwes": [],
         "file": "a.py", "location": {"start_line": 1, "end_line": 5}, "function": "q"},
        {"is_vulnerable": True, "primary_cwe": "CWE-999", "acceptable_cwes": ["CWE-79"],
         "file": "b.py", "location": {"start_line": 10, "end_line": 12}},
        {"is_vulnerable": False, "primary_cwe": "CWE-89", "acceptable_cwes": [],
         "file": "trap.py", "location": {"start_line": 1, "end_line": 2}},
        {"is_vulnerable": True, "primary_cwe": "CWE-693", "acceptable_cwes": [],
         "file": "c.py", "location": {"start_line": 2, "end_line": 2}},
    ]}
    gt, cwes = _realvuln_gt(data, {"CWE-89", "CWE-79"})
    assert [g.file for g in gt] == ["a.py", "b.py"]
    assert cwes == ["CWE-89", "CWE-79"]  # primary counts first, trap dropped


def test_copy_scan_moves_manifests_only(tmp_path):
    src = tmp_path / "group"
    src.mkdir()
    (src / "runs.json").write_text("{}", encoding="utf-8")
    (src / "merged.jsonl").write_text("", encoding="utf-8")
    (src / "opengrep.sarif").write_text("{}", encoding="utf-8")
    (src / "work").mkdir()
    (src / "work" / "x.bin").write_text("x", encoding="utf-8")
    dst = tmp_path / "item" / "vuln"
    _copy_scan(src, dst)
    assert sorted(p.name for p in dst.iterdir()) == ["merged.jsonl", "opengrep.sarif", "runs.json"]
