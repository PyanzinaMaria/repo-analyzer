import io
from collections import Counter
from pathlib import Path

from rich.console import Console

from app.services.report import audit as ar
from bench.eval.match import GTSpan

FIX = Path(__file__).parent / "fixtures" / "toy-py-flask"


def _data(monkeypatch):
    item = {"id": "py-toy", "repo_url": "https://github.com/o/toy", "language": "python", "loc": 50,
            "vuln_commit": "a" * 40, "fix_commit": "b" * 40, "cwe": ["CWE-78"], "cve": "CVE-2000-0001"}
    ranked = [
        {"file": "app.py", "start_line": 18, "end_line": 18, "cwe": ["CWE-78"], "score": 0.9, "origin": "sast+triage",
         "tools": ["bandit", "codeql"], "verdict": "true_positive", "severity": "high", "message": "shell=True",
         "triage": {"verdict": "true_positive", "confidence": 0.9, "source": "request.args['host']",
                    "sink": "subprocess.check_output(shell=True)", "sanitizers": [],
                    "preconditions": "network access", "explanation": "Host is concatenated into a shell command."}},
        {"file": "app.py", "start_line": 47, "end_line": 47, "cwe": ["CWE-502"], "score": 0.5, "origin": "llm",
         "llm": {"title": "Unsafe pickle", "confidence": 0.8, "source_to_sink": ["request.data", "pickle.loads"],
                 "explanation": "Body is unpickled.", "function": "session"}, "title": "Unsafe pickle"},
    ]
    gts = [GTSpan("app.py", 18, 18, 16, 19, "fix_hunk")]
    d = ar.AuditData(item=item, side="vuln", model="m", config="S+T+D@m", ranked=ranked, root=FIX,
                     commit="a" * 40,
                     removed=[{"file": "app.py", "start_line": 26, "tools": ["semgrep"],
                               "result": {"explanation": "Path is constant. More text."}, "score": 0.0}],
                     context={"files": 1, "functions": 5, "entrypoints": 5, "sinks": 6},
                     entry_kinds=Counter({"route": 5}), sink_cwes=Counter({"CWE-78": 1}),
                     sast={"bandit": {"ok": True, "seconds": 1, "findings": 5}}, gt_ranks={"S": 1, "S+T+D@m": 1},
                     gt_locations=gts, gt_hit=lambda e: e["start_line"] == 18)
    return d


def test_render_terminal_wide_and_narrow(monkeypatch):
    d = _data(monkeypatch)
    for width in (130, 80):
        buf = io.StringIO()
        ar.render(d, Console(file=buf, width=width, force_terminal=False), top=5, details=2, reveal=True)
        out = buf.getvalue()
        assert "Security audit · o/toy" in out
        assert "real 0.90" in out and "Unsafe pickle" in out
        assert "Filtered out by LLM triage (1 false positives)" in out
        assert "matches the known vulnerability" in out
        assert "check_output" in out          # code snippet from the snapshot


def test_render_markdown(monkeypatch):
    md = ar.render_markdown(_data(monkeypatch), reveal=True)
    assert md.startswith("# Security audit: [o/toy](https://github.com/o/toy)")
    assert "[CWE-78](https://cwe.mitre.org/data/definitions/78.html)" in md and "★" in md
    assert f"[`app.py:18`](https://github.com/o/toy/blob/{'a' * 40}/app.py#L18)" in md
    assert "[CVE-2000-0001](https://nvd.nist.gov/vuln/detail/CVE-2000-0001)" in md
    assert "**Flow:** request.args['host'] → subprocess.check_output(shell=True)" in md
    assert ">  18" in md


def test_svg_export(monkeypatch, tmp_path):
    p = tmp_path / "a.svg"
    ar.render_to_svg(_data(monkeypatch), p, width=100, top=3, details=1)
    assert p.read_text(encoding="utf-8").lstrip().startswith("<svg")


def test_render_markdown_without_repo_url(monkeypatch):
    """Server mode: an uploaded workspace has no repository URL or commit; locations are plain text."""
    d = _data(monkeypatch)
    d.item = {"name": "upload-1", "language": "python", "loc": 50}
    d.commit = None
    md = ar.render_markdown(d)
    assert md.startswith("# Security audit: upload-1")
    first_row = md.split("## Findings")[1].splitlines()[4]
    assert "`app.py:18`" in first_row and "](https://github" not in first_row
