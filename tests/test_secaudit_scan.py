"""Analyzer pipeline with the secaudit stages: static stage -> LLM stage -> ranking -> reports."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from app.ai import pipeline
from app.ai.config import AiSettings
from app.sast.engine import LanguageRun, merged_to_finding
from app.sast.normalize import MergedFinding
from app.services.scan.ranking import audit_data, ordered, rank_scan
from app.services.report.audit import render_markdown

FIXTURES = Path(__file__).parent / "fixtures"


def _merged(fid: str, line: int, cwe: str, tools: list[str], sev: str = "high") -> MergedFinding:
    return MergedFinding(id=fid, item_id="toy", side="adhoc", file="app.py", start_line=line, end_line=line,
                         cwe=[cwe], tools=tools, rule_ids=[f"{tools[0]}-rule"], severity=sev,
                         messages=[f"{cwe} message"], members=[fid])


def _ai(**kw) -> AiSettings:
    base = dict(enabled=True, provider="openai_compatible", base_url="https://openrouter.ai/api/v1", model="m",
                api_key="k", timeout_seconds=10, max_files=3, max_file_bytes=40000, max_findings=10)
    base.update(kw)
    return AiSettings(**base)


def _run_with_context(tmp_path: Path) -> tuple[Path, LanguageRun]:
    from app.context.build import build_snapshot_context

    root = tmp_path / "toy"
    shutil.copytree(FIXTURES / "toy-py-flask", root)
    run = LanguageRun(language="python", work_dir=tmp_path / "work")
    run.context = build_snapshot_context(root, "python", run.context_dir)
    run.merged = [_merged("a1", 18, "CWE-78", ["bandit", "semgrep"]), _merged("b2", 26, "CWE-22", ["semgrep"]),
                  _merged("c3", 52, "CWE-327", ["bandit"], "low")]
    run.loc = 60
    return root, run


def test_wanted_modes():
    assert pipeline.wanted_modes(_ai(), None) == (["triage", "discovery"], None)
    assert pipeline.wanted_modes(_ai(enabled=False), None) == ([], "disabled_in_config")
    assert pipeline.wanted_modes(_ai(enabled=False), True)[0] == ["triage", "discovery"]
    assert pipeline.wanted_modes(_ai(), False) == ([], "disabled_by_request")
    assert pipeline.wanted_modes(_ai(api_key=None), None) == ([], "missing_api_key")
    assert pipeline.wanted_modes(_ai(modes=("review",)), None) == ([], "no_llm_modes")


def test_llm_stage_ranking_and_audit(tmp_path, monkeypatch):
    root, run = _run_with_context(tmp_path)

    def fake_triage(client, model, snap, language, findings, *a, **k):
        assert [f.id for f in findings] == ["a1", "b2", "c3"]
        verdicts = {"a1": ("true_positive", 0.9), "b2": ("false_positive", 0.8), "c3": ("uncertain", 0.4)}
        rows = []
        for f in findings:
            v, c = verdicts[f.id]
            res = {"verdict": v, "confidence": c, "cwe": f.cwe[0], "source": "request.args", "sink": "sink()",
                   "sanitizers": [], "preconditions": None, "explanation": f"{v} because reasons."}
            score = c if v == "true_positive" else (0.5 * c if v == "uncertain" else 0.0)
            rows.append({"finding_id": f.id, "file": f.file, "start_line": f.start_line, "end_line": f.end_line,
                         "cwe": f.cwe, "tools": f.tools, "result": res, "score": score, "pending": False})
        return rows

    def fake_discovery(client, model, snap, language, loc, merged, *a, **k):
        return [{"file": "app.py", "start_line": 47, "end_line": 47, "cwe": "CWE-502", "confidence": 0.85,
                 "score": 0.85, "title": "pickle.loads on request body", "function": "session",
                 "source_to_sink": ["request.data", "pickle.loads"], "explanation": "Body is unpickled.",
                 "exploit_sketch": "send a pickle", "support": 1}]

    monkeypatch.setattr(pipeline, "triage_findings", fake_triage)
    monkeypatch.setattr(pipeline, "discover_functions", fake_discovery)
    results, meta = pipeline.run_llm_stage(_ai(), root, [run], tmp_path / "data", client=object())
    assert meta["status"] == "completed" and meta["modes"] == ["triage", "discovery"]

    findings = [merged_to_finding(m, "python") for m in run.merged]
    ranking = rank_scan(root, findings, [run], results)
    assert ranking.config == "S+T+D"
    by_cluster = {f.extra["cluster_id"]: f for f in findings}
    assert by_cluster["b2"].extra["dismissed"] is True                      # false positive removed
    assert by_cluster["a1"].extra["verdict"] == "true_positive"
    assert by_cluster["a1"].extra["rank"] == 1
    assert "subprocess" in "\n".join(by_cluster["a1"].extra["snippet"]["lines"])
    [llm] = ranking.new_findings
    assert llm.source == "ai-discovery" and llm.cwe == "CWE-502" and llm.severity.value == "critical"
    all_findings = ordered(findings + ranking.new_findings)
    assert all_findings[-1].extra.get("dismissed")

    data = audit_data(root, "toy", [run], ranking, "m")
    md = render_markdown(data)
    assert md.startswith("# Security audit: toy")
    assert "pickle.loads on request body" in md and "Filtered out by triage (1)" in md
    assert data.context["functions"] > 0 and data.entry_kinds


def test_llm_stage_soft_fails_on_quota(tmp_path, monkeypatch):
    from app.ai.llm import DailyLimitReached

    root, run = _run_with_context(tmp_path)

    def boom(*a, **k):
        raise DailyLimitReached("limit")

    monkeypatch.setattr(pipeline, "triage_findings", boom)
    results, meta = pipeline.run_llm_stage(_ai(), root, [run], tmp_path / "data", client=object())
    assert meta["status"] == "partial" and "DailyLimitReached" in meta["error"]
    ranking = rank_scan(root, [merged_to_finding(m, "python") for m in run.merged], [run], results)
    assert ranking.config == "S"


@pytest.mark.tools
@pytest.mark.parametrize("fixture,tools", [("toy-py-flask", "bandit,semgrep"), ("toy-js-express", "eslint,semgrep")])
def test_full_scan_of_toy_app(fixture, tools, client, tmp_path, monkeypatch):
    """Real analyzers through the HTTP API: planted bugs are found, ranked and documented."""
    from app.sast.tools import eslint_paths, which

    needed = tools.split(",")
    if not which("semgrep") or ("eslint" in needed and not eslint_paths()):
        pytest.skip("analyzers not installed (run scripts/setup.sh)")
    monkeypatch.setenv("SECAUDIT_SAST_TOOLS", tools)
    exp = json.loads((FIXTURES / fixture / "expected.json").read_text())
    project = client.post("/api/v1/projects", json={"source_type": "local_path",
                                                    "local_path": str(FIXTURES / fixture), "name": fixture}).json()
    scan = client.post(f"/api/v1/projects/{project['id']}/scans").json()
    assert scan["status"] == "completed", scan
    base = f"/api/v1/projects/{project['id']}/scans/{scan['id']}"
    result = client.get(f"{base}/result").json()
    found = {(f["file"], f["line"]) for f in result["findings"] if f["extra"].get("rank")}
    hits = [p for p in exp["planted"] if any(f == p["file"] and abs(ln - p["line"]) <= 3 for f, ln in found)]
    assert len(hits) >= 3, (hits, found)
    assert result["meta"]["ranking"] == "S"
    assert result["meta"]["attack_surface"]["context"]["entrypoints"] >= 1
    audit = client.get(f"{base}/reports/audit", params={"format": "markdown"})
    assert audit.status_code == 200 and audit.text.startswith(f"# Security audit: {fixture}")
