from app.sast.normalize import merge, normalize, rank_sast
from app.sast.sarif import FlowStep, RawFinding


def raw(tool, rule, line, cwe, file="a.py", sev="medium", flow=None):
    return RawFinding(tool=tool, rule_id=rule, cwe=cwe, severity=sev, file=file, start_line=line,
                      end_line=line, message=f"{tool} {rule}", dataflow=flow)


def test_normalize_dedupes_same_tool_rule_line():
    fs = normalize([raw("semgrep", "r1", 10, ["CWE-78"]), raw("semgrep", "r1", 10, ["CWE-78"])], "it", "vuln")
    assert len(fs) == 1
    assert fs[0].item_id == "it" and fs[0].side == "vuln"
    assert len(fs[0].id) == 16


def test_merge_across_tools_within_tolerance_and_cwe():
    flow = [FlowStep(file="a.py", line=5), FlowStep(file="a.py", line=12)]
    fs = normalize([
        raw("semgrep", "shell", 10, ["CWE-78"]),
        raw("bandit", "B602", 12, ["CWE-78"], sev="high"),
        raw("codeql", "py/command-line-injection", 13, ["CWE-78", "CWE-88"], flow=flow),
        raw("bandit", "B608", 11, ["CWE-89"]),          # different CWE: own cluster
        raw("semgrep", "shell", 30, ["CWE-78"]),        # too far: own cluster
        raw("semgrep", "shell", 10, ["CWE-78"], file="b.py"),  # other file
    ], "it", "vuln")
    m = merge(fs, tol=3)
    assert len(m) == 4
    big = next(x for x in m if x.file == "a.py" and x.start_line == 10)
    assert big.tools == ["bandit", "codeql", "semgrep"]
    assert (big.start_line, big.end_line) == (10, 13)
    assert big.severity == "high"
    assert big.dataflow and big.dataflow[-1].line == 12
    assert set(big.cwe) == {"CWE-78", "CWE-88"}


def test_merge_eval_family():
    fs = normalize([raw("eslint", "security/detect-eval-with-expression", 16, ["CWE-95"], file="s.js"),
                    raw("codeql", "js/code-injection", 16, ["CWE-94"], file="s.js")], "it", "vuln")
    assert len(merge(fs)) == 1


def test_no_cwe_only_merges_on_same_line():
    fs = normalize([raw("t1", "a", 5, []), raw("t2", "b", 5, []), raw("t3", "c", 6, [])], "it", "vuln")
    assert sorted(len(m.members) for m in merge(fs)) == [1, 2]


def test_rank_by_agreement_then_severity():
    fs = normalize([
        raw("semgrep", "x", 50, ["CWE-22"], sev="high"),
        raw("semgrep", "y", 10, ["CWE-78"], sev="low"),
        raw("bandit", "B602", 10, ["CWE-78"], sev="low"),
        raw("semgrep", "z", 90, ["CWE-79"], sev="critical"),
    ], "it", "vuln")
    ranked = rank_sast(merge(fs))
    assert ranked[0].start_line == 10  # two tools agree
    assert ranked[1].severity == "critical"
