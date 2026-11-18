"""Stage 0 acceptance: SAST finds every planted bug in the toy fixtures (needs analyzers)."""

import json
from pathlib import Path

import pytest

from app.core.yaml_configs import load_sast_config
from app.sast.run import run_tools_isolated
from app.sast.tools import eslint_paths, which

FIXTURES = Path(__file__).parent / "fixtures"
TOL = 3


def _tools_for(lang):
    tools = []
    if which("semgrep"):
        tools.append("semgrep")
    if which("codeql"):
        tools.append("codeql")
    if lang == "python" and which("bandit"):
        tools.append("bandit")
    if lang != "python" and which("node") and eslint_paths():
        tools.append("eslint")
    return tools


@pytest.mark.tools
@pytest.mark.parametrize("fixture", ["toy-py-flask", "toy-js-express"])
def test_planted_bugs_found(fixture, tmp_path):
    exp = json.loads((FIXTURES / fixture / "expected.json").read_text())
    tools = _tools_for(exp["language"])
    if len(tools) < 2:
        pytest.skip("analyzers not installed (run scripts/setup.sh)")
    results = run_tools_isolated(FIXTURES / fixture, exp["language"], tmp_path, tools, load_sast_config(),
                                 item_id=fixture, side="adhoc")
    failed = {t: r.error for t, r in results.items() if not r.ok}
    assert not failed, failed
    findings = [json.loads(line) for line in (tmp_path / "findings.jsonl").read_text().splitlines()]
    missing = []
    for p in exp["planted"]:
        hits = [f for f in findings if f["file"] == p["file"] and abs(f["start_line"] - p["line"]) <= TOL]
        if not hits:
            missing.append(p)
    assert not missing, f"planted bugs not found: {missing}"
    # every tool must contribute at least one finding (guards against silently empty scans)
    by_tool = {f["tool"] for f in findings}
    assert set(tools) <= by_tool, f"tools with no findings: {set(tools) - by_tool}"
