from collections import Counter

import pytest
from pydantic import ValidationError

from bench.build import Selector, assign_ids, normalize_cwes
from bench.schemas import BenchmarkItem, norm_repo_url, parse_commit_url
from bench.sources.secbenchjs import parse_sink
from bench.config import load_benchmark_config


def test_commit_url_parsing():
    assert parse_commit_url("https://github.com/o/r/commit/ABCDEF1234567") == ("https://github.com/o/r", "abcdef1234567")
    assert parse_commit_url("https://github.com/nodeca/js-yaml/pull/480/commits/e18afbf1edca") == (
        "https://github.com/nodeca/js-yaml", "e18afbf1edca")
    assert parse_commit_url("https://gitlab.com/o/r/-/commit/abc1234") is None
    assert norm_repo_url("git+https://github.com/o/r.git") == "https://github.com/o/r"


def test_parse_sink():
    assert parse_sink("lib/encode.js:6:10") == ("lib/encode.js", 6)
    assert parse_sink("./index.js:118") == ("index.js", 118)
    assert parse_sink("n/a") is None


def test_normalize_cwes_aliases_and_order():
    cfg = load_benchmark_config()
    assert normalize_cwes(["CWE-20", "CWE-77"], cfg) == ["CWE-78", "CWE-20"]
    assert normalize_cwes(["CWE-915", "CWE-1321"], cfg) == ["CWE-1321"]
    assert normalize_cwes(["NVD-CWE-noinfo"], cfg) == []


def _cand(i, cwe, repo=None, src=3):
    return {"id": f"c{i}", "primary_cwe": cwe, "repo_url": repo or f"https://github.com/o/r{i}",
            "best_source": src}


def test_selector_caps_cwe_and_repo():
    cands = [_cand(i, "CWE-79") for i in range(10)] + [_cand(100 + i, "CWE-22") for i in range(10)]
    cands += [_cand(200, "CWE-89", repo="https://github.com/o/same"),
              _cand(201, "CWE-89", repo="https://github.com/o/same")]
    sel = Selector(cands, quota=8, cwe_cap=3, seed=1, per_repo=1, used_repos=Counter())
    while not sel.done:
        batch = sel.next_batch(4)
        if not batch:
            break
        for c in batch:
            sel.offer(c, {"status": "ok", "tangled": False})
    got = Counter(c["primary_cwe"] for c, _ in sel.accepted)
    assert len(sel.accepted) == 7          # 3 + 3 + 1 (second same-repo item is skipped)
    assert got["CWE-79"] == 3 and got["CWE-22"] == 3 and got["CWE-89"] == 1


def test_selector_prefers_better_source():
    cands = [_cand(i, "CWE-78", src=3) for i in range(5)] + [_cand(9, "CWE-78", src=0)]
    sel = Selector(cands, quota=1, cwe_cap=1, seed=7, per_repo=1, used_repos=Counter())
    assert sel.next_batch(1)[0]["id"] == "c9"


def test_selector_rejects_tangled_and_failures():
    cands = [_cand(i, "CWE-78") for i in range(3)]
    sel = Selector(cands, quota=2, cwe_cap=2, seed=1, per_repo=1, used_repos=Counter())
    b = sel.next_batch(3)
    assert not sel.offer(b[0], {"status": "ok", "tangled": True})
    assert not sel.offer(b[1], {"status": "rejected", "reason": "x"})
    assert sel.offer(b[2], {"status": "ok", "tangled": False})


def test_assign_ids_unique():
    pool = [{"language": "python", "cve": "CVE-1", "ghsa": None, "repo_url": "https://github.com/a/b",
             "fix_commit": "aaaaaaa1"},
            {"language": "python", "cve": "CVE-1", "ghsa": None, "repo_url": "https://github.com/a/b",
             "fix_commit": "bbbbbbb2"},
            {"language": "typescript", "cve": None, "ghsa": None, "repo_url": "https://github.com/a/c",
             "fix_commit": "ccccccc3"}]
    assign_ids(pool)
    assert [p["id"] for p in pool] == ["py-CVE-1", "py-CVE-1-bbbbbbb", "js-a-c-ccccccc"]


def test_benchmark_item_schema():
    base = dict(id="x", language="python", repo_url="https://github.com/a/b", vuln_commit="1", fix_commit="2",
                cwe=["CWE-22"], loc=3000, split="test", sources=["osv"])
    with pytest.raises(ValidationError):
        BenchmarkItem(**base, gt_locations=[])
    it = BenchmarkItem(**base, gt_locations=[{"file": "a.py", "kind": "fix_hunk", "start_line": 1, "end_line": 2}])
    assert it.quality.manually_checked is False
