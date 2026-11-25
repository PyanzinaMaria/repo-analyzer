"""DAST benchmark: offline tests for config, OpenAPI generation, GT matching, adapter
parsers and eval/compare rendering. No scanners, no docker, no network involved."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from bench.config import Paths
from bench.dast.compare import write_comparison
from bench.dast.config import DastFinding, TargetInfo, load_dast_config
from bench.dast.eval import evaluate
from bench.dast import match as match_mod
from bench.dast.match import (by_category, by_cwe, classify_item, classify_owasp,
                              owasp_tests)
from bench.dast.openapi import discover_routes, routes_to_openapi
from bench.dast.scan import _cached


# --------------------------------------------------------------------------- config


def test_load_dast_config_tools():
    cfg = load_dast_config()
    assert set(cfg.tools) == {"zap", "wapiti", "nuclei", "offat", "nikto"}
    assert cfg.tool("zap").image.startswith("ghcr.io/zaproxy")
    assert cfg.scan_timeout_s == 1800
    assert cfg.tool("nuclei").templates_dir is None


def test_load_dast_config_realvuln_overrides():
    cfg = load_dast_config()
    ov = cfg.realvuln_overrides
    assert "rv-juice-shop" in ov and ov["rv-juice-shop"].image
    assert ov["rv-realvuln-altoroj"].java_war and ov["rv-dvpwa"].port == 8080
    assert cfg.watchdog_timeout_s > cfg.boot_timeout_s


def test_sanitize_compose_envfiles(tmp_path: Path):
    import yaml as pyyaml

    from bench.dast.targets import _sanitize_compose_envfiles

    compose = tmp_path / "docker-compose.yml"
    compose.write_text(yaml.safe_dump({
        "services": {
            "app": {"env_file": ["./vars.env", "./present.env"], "image": "x"},
            "db": {"env_file": "db.env"},
        }}), encoding="utf-8")
    (tmp_path / "present.env").write_text("A=1\n", encoding="utf-8")
    created = _sanitize_compose_envfiles(compose)
    assert (tmp_path / "vars.env").is_file() and (tmp_path / "db.env").is_file()
    assert len(created) == 2
    assert _sanitize_compose_envfiles(compose) == []  # idempotent


# --------------------------------------------------------------------------- openapi


def test_discover_routes_java_and_python(tmp_path: Path):
    jdir = tmp_path / "src" / "main" / "java" / "org" / "owasp"
    jdir.mkdir(parents=True)
    (jdir / "T.java").write_text(
        '@WebServlet("/pathtraver-00/BenchmarkTest00001")\n'
        'public class T {}\n'
        '@WebServlet(value = "/sqli-00/BenchmarkTest00002")\n'
        'public class T2 {}\n', encoding="utf-8")
    pdir = tmp_path / "testcode"
    pdir.mkdir()
    (pdir / "BenchmarkTest00001.py").write_text(
        "@app.route('/benchmark/sqli-00/BenchmarkTest00001', methods=['GET'])\n"
        "def f(): pass\n"
        "@app.route('/benchmark/xss-00/BenchmarkTest00002')\n"
        "def g(): pass\n", encoding="utf-8")
    rj = discover_routes(tmp_path, "owasp-java")
    rp = discover_routes(tmp_path, "owasp-python")
    assert rj == {"/pathtraver-00/BenchmarkTest00001": ["GET", "POST"],
                  "/sqli-00/BenchmarkTest00002": ["GET", "POST"]}
    assert rp == {"/benchmark/sqli-00/BenchmarkTest00001": ["GET"],
                  "/benchmark/xss-00/BenchmarkTest00002": ["GET"]}
    doc = routes_to_openapi(rp, title="t")
    path = doc["paths"]["/benchmark/sqli-00/BenchmarkTest00001"]
    assert path["get"]["parameters"][1]["in"] == "cookie"
    assert "post" not in path  # GET-only route stays GET


# --------------------------------------------------------------------------- matching


def test_test_name_from_url():
    # via module alias: pytest would collect the imported `test_name` symbol otherwise
    assert match_mod.test_name("http://h:8443/sqli-00/BenchmarkTest00042?x=1") == "BenchmarkTest00042"
    assert match_mod.test_name("http://h/benchmark/xss-00/BenchmarkTest00123") == "BenchmarkTest00123"
    assert match_mod.test_name("http://h/index.html") is None
    assert match_mod.test_name("") is None


CSV = "\n".join([
    "# test name, category, real vulnerability, cwe, Benchmark version: 1.2",
    "BenchmarkTest00001,sqli,true,89",
    "BenchmarkTest00002,sqli,false,89",
    "BenchmarkTest00003,xss,true,79",
])


def F(url: str, cwe: list[str] | None = None, rule: str = "r") -> DastFinding:
    return DastFinding(tool="t", rule_id=rule, title="x", cwe=cwe or [], url=url)


def test_owasp_tests_keeps_false_rows():
    tests = owasp_tests(CSV.splitlines())
    assert len(tests) == 3
    assert tests["BenchmarkTest00002"].vulnerable is False
    assert tests["BenchmarkTest00003"].cwe == "CWE-79"


def test_classify_owasp_tp_fp_non_test():
    tests = owasp_tests(CSV.splitlines())
    findings = [
        F("http://h/sqli-00/BenchmarkTest00001", ["CWE-89"]),     # TP with cwe
        F("http://h/sqli-00/BenchmarkTest00001", ["CWE-89"]),     # dedup
        F("http://h/sqli-00/BenchmarkTest00002", ["CWE-89"]),     # FP on false test
        F("http://h/xss-00/BenchmarkTest00003"),                  # TP without cwe -> lenient hit, no cwe-agree
        F("http://h/admin"),                                      # non-test URL
    ]
    m = classify_owasp(findings, tests)
    assert (m["tp"], m["fp"], m["fn"]) == (2, 2, 0)  # both true tests hit -> fn=0
    assert m["non_test_findings"] == 1
    assert m["cwe_labelled"] == 1  # the no-cwe XSS hit stays lenient but unlabeled
    assert m["cwe_agree_hits"] == 1


def test_classify_owasp_cwe_mismatch_counts_lenient_hit():
    tests = owasp_tests(CSV.splitlines())
    m = classify_owasp([F("http://h/sqli-00/BenchmarkTest00001", ["CWE-79"])], tests)
    assert m["tp"] == 1 and m["cwe_agree_hits"] == 0


def test_by_category_and_cwe():
    tests = owasp_tests(CSV.splitlines())
    findings = [F("http://h/sqli-00/BenchmarkTest00001", ["CWE-89"]),
                F("http://h/sqli-00/BenchmarkTest00002", ["CWE-89"]),
                F("http://h/xss-00/BenchmarkTest00003", ["CWE-79"])]
    cat = by_category(findings, tests)
    assert cat == {"sqli": {"n_true": 1, "tp": 1, "fp": 1}, "xss": {"n_true": 1, "tp": 1, "fp": 0}}
    cwe = by_cwe(findings, tests)
    assert cwe == {"CWE-79": {"n_true": 1, "tp": 1, "fp": 0}, "CWE-89": {"n_true": 1, "tp": 1, "fp": 1}}


def test_classify_item_cwe_overlap():
    m1 = classify_item([F("http://h/", ["CWE-89"])], ["CWE-89"])
    assert m1 == {"n_items": 1, "items_hit": 1, "tp": 1, "fp": 0, "fn": 0}
    # family overlap: eval -> code-injection family counts for CWE-94
    m2 = classify_item([F("http://h/", ["CWE-95"])], ["CWE-94"])
    assert m2["items_hit"] == 1
    m3 = classify_item([F("http://h/")], ["CWE-89"])  # no cwe at all -> FP, miss
    assert m3 == {"n_items": 1, "items_hit": 0, "tp": 0, "fp": 1, "fn": 1}


# --------------------------------------------------------------------------- adapter parsers


def test_wapiti_parse_both_shapes():
    dict_shape = {"vulnerabilities": {"SQL Injection": [
        {"url": "http://h/sqli-00/BenchmarkTest00001", "method": "POST", "parameter": "param",
         "info": "injection found"}]}}
    f = __import__("bench.dast.adapters.wapiti", fromlist=["parse"]).parse(dict_shape)
    assert f[0].cwe == ["CWE-89"] and f[0].parameter == "param"
    list_shape = {"vulnerabilities": [{"category": "XSS", "type": "vulnerability",
                                       "url": "http://h/x", "method": "GET"}]}
    f2 = __import__("bench.dast.adapters.wapiti", fromlist=["parse"]).parse(list_shape)
    assert f2[0].cwe == ["CWE-79"]


def test_nuclei_parse_line():
    mod = __import__("bench.dast.adapters.nuclei", fromlist=["parse_line"])
    row = json.dumps({
        "template-id": "sqli-error-based", "matched-at": "http://h/BenchmarkTest00001?a=1",
        "info": {"name": "SQLI", "severity": "high",
                 "classification": {"cwe-id": ["CWE-89", "cwe-20"]}}})
    f = mod.parse_line(row)
    assert f.cwe == ["CWE-89", "CWE-20"] and f.severity == "high" and "BenchmarkTest00001" in f.url
    assert mod.parse_line("not json") is None


def test_nikto_parse_tolerant_json():
    mod = __import__("bench.dast.adapters.nikto", fromlist=["parse"])
    # nikto 2.5 real shape: top-level ARRAY of host records, item text in `msg`, url is a path
    text = json.dumps([
        {"host": "h", "ip": "1.2.3.4", "port": "8080", "vulnerabilities": [
            {"id": "013587", "msg": "/admin/ found", "method": "GET", "url": "/admin"},
            {"id": "x", "msg": "cookie without flags", "method": "GET", "url": "/"}]}])
    fs = mod.parse(json.loads(text))
    assert len(fs) == 2
    assert fs[0].cwe == ["CWE-16"] and fs[0].url == "http://h:8080/admin"
    assert fs[1].url == "http://h:8080/"
    # tolerant decode: concatenated objects (log noise around the report) still parse
    from bench.dast.adapters.base import iter_json_objects
    old = '{"vulnerabilities": [{"item": "/admin/ found"}]}{"vulnerabilities": []}'
    assert len(list(iter_json_objects(old))) == 2


def test_offat_parse_maps_cwe():
    mod = __import__("bench.dast.adapters.offat", fromlist=["parse"])
    payload = [{"test_name": "Unrestricted Endpoint Access Test", "url": "/BenchmarkTest00001",
                "method": "GET", "is_vulnerable": True},
               {"test_name": "BOLA Route Test", "request": {"url": "/x"}, "is_vulnerable": False}]
    fs = mod.parse(payload)
    assert fs[0].cwe == ["CWE-285"] and fs[1].cwe == ["CWE-639"]
    assert fs[1].url == "/x"


def test_zap_skip_without_docker(tmp_path: Path, monkeypatch):
    import bench.dast.adapters.zap as zap_mod

    monkeypatch.setattr(zap_mod, "which_docker", lambda: None)
    res, findings = zap_mod.run(TargetInfo(target_id="t", kind="owasp-python",
                                           host_url="http://127.0.0.1:5000",
                                           scan_url="http://c:5000"),
                                tmp_path, load_dast_config())
    assert res.skipped and not res.ok and "docker" in res.reason and findings == []


def test_zap_instance_findings(tmp_path: Path, monkeypatch):
    import bench.dast.adapters.zap as zap_mod

    alert = {"pluginid": "40018", "name": "SQL Injection", "riskcode": "3", "cweid": "89",
             "instances": [{"uri": "http://h/BenchmarkTest00001", "method": "POST",
                            "param": "param", "evidence": "'"}]}
    fs = zap_mod._instance_findings(alert, "zap")
    assert fs[0].cwe == ["CWE-89"] and fs[0].severity == "high" and fs[0].parameter == "param"


# --------------------------------------------------------------------------- eval + compare


@pytest.fixture()
def owasp_corpus(tmp_path: Path) -> Paths:
    """Synthetic owasp-python corpus: benchmark.jsonl, pinned worktree CSV, one target."""
    paths = Paths(root=tmp_path)
    gid = "owasp-benchmark__benchmarkpython__f1291485808b"
    (paths.snapshots / "_groups" / gid).mkdir(parents=True)
    (paths.snapshots / "_groups" / gid / "expectedresults-0.1.csv").write_text(CSV, encoding="utf-8")
    io = __import__("app.core.io", fromlist=["write_jsonl"])
    io.write_jsonl(paths.benchmark, [{
        "id": "owasp-python-sqli", "language": "python",
        "repo_url": "https://github.com/OWASP-Benchmark/BenchmarkPython",
        "vuln_commit": "f1291485808b66e20ddb6b01b10dc71b3df8c8ba", "fix_commit": "",
        "cwe": ["CWE-89"], "loc": 10, "gt_locations": [], "split": "dev"}])
    paths.dast.mkdir(parents=True)
    (paths.dast / "targets.json").write_text(json.dumps({
        "owasp-python-app": {"kind": "owasp-python", "status": "up",
                             "host_url": "http://127.0.0.1:5000",
                             "scan_url": "http://c:5000", "network": "n"}},
        ensure_ascii=False), encoding="utf-8")
    tdir = paths.dast / "owasp-python-app"
    tdir.mkdir()
    io.write_jsonl(tdir / "zap.findings.jsonl", [
        {"tool": "zap", "rule_id": "40018", "title": "SQLi", "severity": "high",
         "cwe": ["CWE-89"], "url": "http://h/sqli-00/BenchmarkTest00001", "method": "POST"},
        {"tool": "zap", "rule_id": "40012", "title": "XSS", "severity": "medium",
         "cwe": ["CWE-79"], "url": "http://h/xss-00/BenchmarkTest00003", "method": "GET"}])
    (tdir / "zap.status.json").write_text(json.dumps({"ok": True, "seconds": 61.5}), encoding="utf-8")
    return paths


def test_evaluate_owasp(owasp_corpus: Paths, tmp_path: Path, monkeypatch):
    import bench.dast.eval as eval_mod

    monkeypatch.setattr(eval_mod, "load_external_config",
                        lambda: type("S", (), {"owasp_python": type("C", (), {"csv": "expectedresults-0.1.csv"})})())
    report = evaluate("owasp-python", paths=owasp_corpus)
    metrics = json.loads((owasp_corpus.results / "dast_metrics.json").read_text(encoding="utf-8"))
    assert metrics["mode"] == "owasp" and metrics["tools"] == ["zap"]
    m = metrics["metrics"]["zap"]
    assert (m["tp"], m["fp"], m["fn"]) == (2, 0, 0)  # both true tests hit, no false hits
    assert m["precision"] == 1.0 and m["recall"] == 1.0
    assert m["cwe_agreement"] == 1.0  # both hits carry matching CWEs
    assert m["seconds"] == 61.5
    assert "dast_report.md" in report.name
    assert "| zap |" in report.read_text(encoding="utf-8")


def test_evaluate_items_mode(tmp_path: Path):
    io = __import__("app.core.io", fromlist=["write_jsonl"])
    paths = Paths(root=tmp_path)
    io.write_jsonl(paths.benchmark, [
        {"id": "rv-a", "cwe": ["CWE-89"]}, {"id": "rv-b", "cwe": ["CWE-79"]}])
    paths.dast.mkdir(parents=True)
    (paths.dast / "targets.json").write_text(json.dumps({
        "rv-a": {"kind": "realvuln", "status": "up", "host_url": "http://127.0.0.1:1",
                 "scan_url": "http://a:8000", "network": "n"},
        "rv-b": {"kind": "realvuln", "status": "boot_failed", "reason": "x"}}, ensure_ascii=False),
        encoding="utf-8")
    tdir = paths.dast / "rv-a"
    tdir.mkdir()
    io.write_jsonl(tdir / "nuclei.findings.jsonl", [
        {"tool": "nuclei", "rule_id": "sqli", "title": "s", "severity": "high",
         "cwe": ["CWE-89"], "url": "http://127.0.0.1:1/x", "method": "GET"}])
    (tdir / "nuclei.status.json").write_text(json.dumps({"ok": True, "seconds": 3}), encoding="utf-8")
    evaluate("realvuln", paths=paths)
    metrics = json.loads((paths.results / "dast_metrics.json").read_text(encoding="utf-8"))
    assert metrics["mode"] == "items"
    m = metrics["metrics"]["nuclei"]
    assert m["n_items"] == 1 and m["items_hit"] == 1 and m["recall_items"] == 1.0  # rv-b not up


def test_compare_renders_tables(tmp_path: Path):
    root = tmp_path / "owasp-python"
    (root / "results").mkdir(parents=True)
    (root / "results" / "dast_metrics.json").write_text(json.dumps({
        "kind": "owasp-python", "mode": "owasp", "generated_at": "2026-11-24T00:00:00+00:00",
        "tools": ["zap"], "scan_timeout_s": 1800,
        "metrics": {"zap": {"tp": 2, "fp": 1, "fn": 1, "precision": 0.6667, "recall": 0.6667,
                            "f1": 0.6667, "tp_rate": 0.6667, "fp_rate": 0.5, "cwe_agreement": 0.5,
                            "non_test_findings": 1, "seconds": 91.0}},
        "coverage": {"zap": {"ok": 1}}}, ensure_ascii=False), encoding="utf-8")
    out = tmp_path / "docs" / "DAST.md"
    write_comparison([root], out)
    text = out.read_text(encoding="utf-8")
    assert "## owasp-python" in text and "| zap | 2 | 1 | 1 |" in text and "67%" in text


def test_scan_cache(tmp_path: Path):
    st = tmp_path / "zap.status.json"
    fd = tmp_path / "zap.findings.jsonl"
    assert not _cached(st, fd, force=False)
    st.write_text(json.dumps({"ok": True}), encoding="utf-8")
    fd.write_text("", encoding="utf-8")
    assert _cached(st, fd, force=False)
    assert not _cached(st, fd, force=True)
    st.write_text(json.dumps({"ok": False, "skipped": False}), encoding="utf-8")
    assert not _cached(st, fd, force=False)
