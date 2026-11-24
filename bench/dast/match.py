"""Match DAST findings to ground truth.

OWASP corpora are scored per HTTP test case against the expectedresults CSV (columns:
`# test name, category, real vulnerability, cwe, ...`): a finding whose URL references a
test name counts as TP on a true test or FP on a false test, deduplicated per test name
(endpoint-level counting, like the upstream Benchmark scoring). RealVuln has no stable
URL->finding mapping, so it is scored per item by CWE overlap.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass

from app.sast.cwe_map import cwe_overlap

TEST_NAME_RE = re.compile(r"BenchmarkTest\d+", re.IGNORECASE)


def test_name(url: str) -> str | None:
    """'http://host/benchmark/sqli-00/BenchmarkTest00001?x=1' -> 'BenchmarkTest00001'."""
    m = TEST_NAME_RE.search(url or "")
    return m.group(0) if m else None


@dataclass
class OwaspTest:
    name: str
    category: str
    vulnerable: bool
    cwe: str


def owasp_tests(lines: list[str]) -> dict[str, OwaspTest]:
    """Per-test ground truth from the expectedresults CSV (keeps false rows, unlike _owasp_categories)."""
    tests: dict[str, OwaspTest] = {}
    for line in lines:
        parts = line.split(",")
        if len(parts) < 4 or parts[2].lower() not in ("true", "false"):
            continue
        name = parts[0].strip()
        tests[name] = OwaspTest(name=name, category=parts[1].strip(),
                                vulnerable=parts[2].lower() == "true",
                                cwe=f"CWE-{parts[3].strip()}")
    return tests


def classify_owasp(findings: list, tests: dict[str, OwaspTest]) -> dict:
    """Endpoint-level counters for one tool: one hit per test name; per-finding cwe agreement."""
    hit_tests: set[str] = set()
    hit_cwe: set[str] = set()
    labelled: set[str] = set()
    non_test: set[tuple[str, str]] = set()
    for f in findings:
        name = test_name(f.url)
        if name is None or name not in tests:
            non_test.add((f.rule_id, f.url))
            continue
        hit_tests.add(name)
        if tests[name].vulnerable:
            if f.cwe:
                labelled.add(name)
                if cwe_overlap(f.cwe, [tests[name].cwe]):
                    hit_cwe.add(name)
    true_hits = {n for n in hit_tests if tests[n].vulnerable}
    false_hits = hit_tests - true_hits
    n_true = sum(1 for t in tests.values() if t.vulnerable)
    n_false = len(tests) - n_true
    return {
        "n_tests": len(tests), "n_true": n_true, "n_false": n_false,
        "tp": len(true_hits), "fp": len(false_hits) + len(non_test), "fn": n_true - len(true_hits),
        "non_test_findings": len(non_test), "cwe_labelled": len(labelled),
        "cwe_agree_hits": len(hit_cwe),
    }


def classify_item(findings: list, cwes: list[str]) -> dict:
    """One tool vs one pinned app repo: hit = any CWE-overlapping finding (endpoint info unused)."""
    hit = any(f.cwe and cwe_overlap(f.cwe, cwes) for f in findings)
    tp = sum(1 for f in findings if f.cwe and cwe_overlap(f.cwe, cwes))
    return {"n_items": 1, "items_hit": int(hit), "tp": tp, "fp": len(findings) - tp,
            "fn": 1 - int(hit)}


def by_category(findings: list, tests: dict[str, OwaspTest]) -> dict[str, dict]:
    """Per OWASP category: n_true/tp/fp among URL-resolvable findings (non-test excluded)."""
    acc: dict[str, dict[str, set[str]]] = defaultdict(lambda: {"tp": set(), "fp": set()})
    seen: set[tuple[str, str]] = set()
    for f in findings:
        name = test_name(f.url)
        if not name or name in seen or name not in tests:
            continue
        seen.add((f.tool, name))
        t = tests[name]
        bucket = acc[t.category]
        (bucket["tp"] if t.vulnerable else bucket["fp"]).add(name)
    n_true: Counter[str] = Counter()
    for t in tests.values():
        if t.vulnerable:
            n_true[t.category] += 1
    return {cat: {"n_true": n_true[cat], "tp": len(v["tp"]), "fp": len(v["fp"])}
            for cat, v in sorted(acc.items())}


def by_cwe(findings: list, tests: dict[str, OwaspTest]) -> dict[str, dict]:
    acc: dict[str, dict[str, set[str]]] = defaultdict(lambda: {"tp": set(), "fp": set()})
    seen: set[str] = set()
    for f in findings:
        name = test_name(f.url)
        if not name or name in seen or name not in tests:
            continue
        seen.add(name)
        t = tests[name]
        (acc[t.cwe]["tp" if t.vulnerable else "fp"]).add(name)
    n_true: Counter[str] = Counter()
    for t in tests.values():
        if t.vulnerable:
            n_true[t.cwe] += 1
    return {cwe: {"n_true": n_true[cwe], "tp": len(v["tp"]), "fp": len(v["fp"])}
            for cwe, v in sorted(acc.items())}
