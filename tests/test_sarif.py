from pathlib import Path

from app.sast.cwe_map import cwe_overlap, norm_cwe
from app.sast.sarif import parse_sarif, rel_path


def _run(driver, results, rules=None, extensions=None, base_ids=None):
    run = {"tool": {"driver": {"name": driver, "rules": rules or []}}, "results": results}
    if extensions:
        run["tool"]["extensions"] = extensions
    if base_ids:
        run["originalUriBaseIds"] = base_ids
    return {"version": "2.1.0", "runs": [run]}


def _loc(uri, line, end=None, base=None, snippet=None):
    region = {"startLine": line}
    if end:
        region["endLine"] = end
    if snippet:
        region["snippet"] = {"text": snippet}
    art = {"uri": uri}
    if base:
        art["uriBaseId"] = base
    return {"physicalLocation": {"artifactLocation": art, "region": region}}


def test_norm_cwe_variants():
    assert norm_cwe("external/cwe/cwe-078") == "CWE-78"
    assert norm_cwe("CWE-89: Improper Neutralization") == "CWE-89"
    assert norm_cwe(22) == "CWE-22"
    assert norm_cwe("1321") == "CWE-1321"
    assert norm_cwe("no cwe here") is None


def test_cwe_family_overlap():
    assert cwe_overlap(["CWE-94"], ["CWE-95"])
    assert cwe_overlap(["CWE-22"], ["CWE-23", "CWE-99"])
    assert not cwe_overlap(["CWE-22"], ["CWE-89"])
    assert not cwe_overlap([], ["CWE-89"])


def test_semgrep_absolute_uri_and_tag_cwe():
    sarif = _run("Semgrep OSS", [{
        "ruleId": "python.lang.security.audit.subprocess-shell-true",
        "level": "error",
        "message": {"text": "shell=True"},
        "locations": [_loc("file:///work/repo/app/run.py", 10, 11)],
    }], rules=[{"id": "python.lang.security.audit.subprocess-shell-true",
                "properties": {"tags": ["CWE-78: OS Command Injection", "security"]}}])
    [f] = parse_sarif(sarif, root=Path("/work/repo"))
    assert f.tool == "semgrep"
    assert f.file == "app/run.py"
    assert (f.start_line, f.end_line) == (10, 11)
    assert f.cwe == ["CWE-78"]
    assert f.severity == "high"


def test_codeql_extension_rules_codeflow_and_basedir():
    sarif = _run("CodeQL", [{
        "ruleId": "py/path-injection",
        "message": {"text": "path depends on user input"},
        "locations": [_loc("app/views.py", 30, base="%SRCROOT%")],
        "codeFlows": [{"threadFlows": [{"locations": [
            {"location": _loc("app/views.py", 22, base="%SRCROOT%", snippet="name = request.args['n']")},
            {"location": _loc("app/views.py", 30, base="%SRCROOT%", snippet="open(p)")},
        ]}]}],
    }], extensions=[{"name": "codeql/python-queries", "rules": [{
        "id": "py/path-injection",
        "properties": {"tags": ["security", "external/cwe/cwe-022", "external/cwe/cwe-023"],
                       "security-severity": "7.5"}}]}])
    [f] = parse_sarif(sarif)
    assert f.tool == "codeql" and f.file == "app/views.py"
    assert f.cwe == ["CWE-22", "CWE-23"]
    assert f.severity == "high"
    assert [s.line for s in f.dataflow] == [22, 30]
    assert f.dataflow[0].snippet.startswith("name")


def test_bandit_manual_cwe_and_result_severity():
    sarif = _run("Bandit", [{
        "ruleId": "B506",
        "message": {"text": "Use of unsafe yaml load."},
        "properties": {"issue_severity": "MEDIUM", "issue_confidence": "HIGH"},
        "locations": [_loc("./app.py", 41)],
    }])
    [f] = parse_sarif(sarif)
    assert f.file == "app.py"
    assert "CWE-502" in f.cwe and "CWE-20" in f.cwe
    assert f.severity == "medium"


def test_eslint_rule_mapping_and_rule_index():
    sarif = _run("ESLint", [{
        "ruleId": "security/detect-eval-with-expression",
        "ruleIndex": 0,
        "level": "warning",
        "message": {"text": "eval with argument of type MemberExpression"},
        "locations": [_loc("file:///home/u/snap/server.js", 16)],
    }], rules=[{"id": "security/detect-eval-with-expression"}])
    [f] = parse_sarif(sarif, root=Path("/home/u/snap"))
    assert f.file == "server.js"
    assert f.cwe == ["CWE-95", "CWE-94"]
    assert f.severity == "medium"


def test_results_without_location_are_skipped():
    sarif = _run("Semgrep", [{"ruleId": "x", "message": {"text": "m"}, "locations": []}])
    assert parse_sarif(sarif) == []


def test_rel_path_windows_uri():
    assert rel_path("file:///C:/proj/src/a.py", Path("C:/proj")) == "src/a.py"
    assert rel_path("src/a%20b.py", None) == "src/a b.py"
