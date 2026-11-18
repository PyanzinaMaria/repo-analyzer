import json

import pytest

from app.core.yaml_configs import BackendSpec, ModelsConfig, ModelSpec

from bench.config import Paths
from app.ai.llm import LLMClient, extract_json
from app.ai.common import assert_no_leak, redact_ids
from app.ai.prompting import render
from app.ai.rank import rank_ST, rrf
from app.ai.schemas import DiscoveryResult, TriageBatchResult, TriageResult
from app.ai.triage import group_findings
from app.sast.normalize import MergedFinding


def test_extract_json_variants():
    assert extract_json('{"a": 1}') == {"a": 1}
    assert extract_json('Sure!\n```json\n{"a": {"b": "}"}}\n```') == {"a": {"b": "}"}}
    assert extract_json('reasoning... {"verdict": "fp"} trailing') == {"verdict": "fp"}
    assert extract_json("no json here") is None


def test_triage_schema_coercions():
    t = TriageResult.model_validate({"verdict": "TP", "confidence": 85, "cwe": "cwe-078",
                                     "sanitizers": "none", "explanation": "x"})
    assert t.verdict == "true_positive" and t.confidence == 0.85 and t.cwe == "CWE-78"
    assert t.sanitizers == ["none"] and t.score == 0.85
    assert TriageResult(verdict="uncertain", confidence=0.6, explanation="e").score == 0.3
    assert TriageResult(verdict="false_positive", confidence=0.9, explanation="e").score == 0.0


def test_discovery_schema():
    d = DiscoveryResult.model_validate({"vulnerabilities": [
        {"file": "a.py", "start_line": 10, "end_line": 5, "cwe": "22", "title": "t", "confidence": 0.7,
         "source_to_sink": "req -> open", "explanation": "e"}]})
    v = d.vulnerabilities[0]
    assert v.end_line == 10 and v.cwe == "CWE-22" and v.source_to_sink == ["req -> open"]


def _mf(file, line, fid=None):
    return MergedFinding(id=fid or f"{file}:{line}", item_id="i", side="vuln", file=file, start_line=line,
                         end_line=line, cwe=["CWE-78"], tools=["semgrep"], rule_ids=["semgrep:r"], severity="high",
                         messages=["shell=True"], members=["m"])


def test_prompts_render_and_leak_guard():
    sys_p, user_p = render("triage", language="python", findings=[_mf("a.py", 3), _mf("a.py", 9)],
                           framework_hints="flask", contexts=["CODE"])
    assert "senior application-security auditor" in sys_p
    assert "## Finding 2" in user_p and "a.py:3-3" in user_p and "CODE" in user_p
    with pytest.raises(AssertionError):
        assert_no_leak("fixes CVE-2023-12345")
    assert "CVE" not in redact_ids("# fix for CVE-2023-12345 and GHSA-abcd-efgh-ijkl")


def _client(tmp_path, mode="live"):
    cfg = ModelsConfig(budget_usd=0.0,
                       backends={"selfhosted": BackendSpec(base_url="http://x/v1", max_concurrency=1)},
                       models=[ModelSpec(id="m", backend="selfhosted")])
    return LLMClient(cfg, mode=mode, data_root=tmp_path)


def test_complete_json_cache_and_repair(tmp_path, monkeypatch):
    c = _client(tmp_path)
    answers = iter(["not json at all", json.dumps({"verdict": "false_positive", "confidence": 0.9,
                                                    "explanation": "sanitized"})])
    calls = []

    def fake_backend(model_id, messages, params):
        calls.append(messages)
        return next(answers), {"prompt_tokens": 10, "completion_tokens": 5}

    monkeypatch.setattr(c, "_call_backend", fake_backend)
    r = c.complete_json("m", "sys", "user", TriageResult)
    assert r.obj is not None and r.obj.verdict == "false_positive"
    assert len(calls) == 2 and "did not match the schema" in calls[1][-1]["content"]
    # second run: both calls come from the cache, no backend calls
    monkeypatch.setattr(c, "_call_backend", lambda *a: (_ for _ in ()).throw(AssertionError("no call")))
    r2 = c.complete_json("m", "sys", "user", TriageResult)
    assert r2.obj == r.obj and r2.cached


def test_export_then_import(tmp_path):
    c = _client(tmp_path, mode="export")
    r = c.complete_json("m", "sys", "user", TriageResult)
    assert r.pending
    c.complete_json("m", "sys", "user", TriageResult)    # same request is not exported twice
    req_file = tmp_path / "llm_batch" / "m.requests.jsonl"
    reqs = [json.loads(line) for line in req_file.read_text().splitlines()]
    assert len(reqs) == 1
    resp = tmp_path / "responses.jsonl"
    resp.write_text(json.dumps({"key": reqs[0]["key"], "model": "m",
                                "text": '{"verdict": "true_positive", "confidence": 0.7, "explanation": "x"}'}) + "\n")
    cached = _client(tmp_path, mode="cache")
    assert cached.import_responses(resp) == 1
    r = cached.complete_json("m", "sys", "user", TriageResult)
    assert r.obj.verdict == "true_positive" and r.cached


def test_rank_st_and_rrf():
    S = [{"id": "a", "file": "x.py", "start_line": 1, "end_line": 1, "cwe": ["CWE-78"], "score": 1, "origin": "sast"},
         {"id": "b", "file": "x.py", "start_line": 50, "end_line": 50, "cwe": ["CWE-22"], "score": .5, "origin": "sast"},
         {"id": "c", "file": "y.py", "start_line": 9, "end_line": 9, "cwe": ["CWE-89"], "score": .2, "origin": "sast"}]
    tri = [{"finding_id": "a", "result": {"verdict": "false_positive"}, "score": 0.0},
           {"finding_id": "b", "result": {"verdict": "true_positive"}, "score": 0.9}]
    st = rank_ST(S, tri)
    assert [e["id"] for e in st] == ["b", "c"]          # a removed, b promoted, c untriaged kept
    L = [{"file": "y.py", "start_line": 10, "end_line": 10, "cwe": ["CWE-89"], "score": .8, "origin": "llm"}]
    fused = rrf([st, L])
    assert fused[0]["file"] == "y.py" and "llm" in fused[0]["origin"] and "sast" in fused[0]["origin"]
    assert len(fused) == 2


def test_group_findings_by_file():
    fs = [_mf("b.py", 1), _mf("a.py", 5), _mf("a.py", 1), _mf("a.py", 9), _mf("c.py", 2)]
    groups = group_findings(fs, per_prompt=2)
    assert [[(f.file, f.start_line) for f in g] for g in groups] == [
        [("a.py", 1), ("a.py", 5)], [("a.py", 9), ("b.py", 1)], [("c.py", 2)]]
    assert len(group_findings(fs * 2, 5)) == 2
    assert sum(len(g) for g in group_findings(fs, 5)) == 5


def test_triage_batch_schema():
    b = TriageBatchResult.model_validate({"results": [
        {"finding": 1, "verdict": "fp", "confidence": 0.9, "explanation": "x"},
        {"finding": 2, "verdict": "true_positive", "confidence": "0.7", "explanation": "y"}]})
    assert [r.verdict for r in b.results] == ["false_positive", "true_positive"]


def test_reasoning_params_go_to_extra_body(tmp_path, monkeypatch):
    from app.ai.llm import EXTRA_BODY_KEYS

    assert "reasoning" in EXTRA_BODY_KEYS
    c = _client(tmp_path)
    c.cfg.models[0].reasoning_headroom = 1000
    seen = {}

    def fake(model_id, messages, params):
        seen.update(params)
        return '{"verdict": "uncertain", "confidence": 0.5, "explanation": "e"}', {}

    monkeypatch.setattr(c, "_call_backend", fake)
    c.complete_json("m", "s", "u", TriageResult, params={"max_tokens": 500})
    assert seen["max_tokens"] == 1500
