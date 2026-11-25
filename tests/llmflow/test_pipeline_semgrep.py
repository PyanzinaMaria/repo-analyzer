"""End-to-end pipeline on tiny repositories (needs Semgrep; skipped otherwise)."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from app.llmflow.semgrep import SemgrepMissing, semgrep_exe


def _has_semgrep() -> bool:
    try:
        semgrep_exe()
        return True
    except SemgrepMissing:
        return False


pytestmark = pytest.mark.skipif(not _has_semgrep(), reason="semgrep not installed")


def write(root: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body), encoding="utf-8")
    return root


def scan(root: Path, tmp_path: Path, **kw):
    from app.llmflow.pipeline import Options, run

    return run(root, tmp_path / "out", Options(**kw))


LLM = """\
    import os
    from openai import OpenAI
    client = OpenAI()

    def ask(question):
        r = client.chat.completions.create(model=os.getenv("M", "gpt-4o"),
                                           messages=[{"role": "user", "content": question}])
        return r.choices[0].message.content
    """


def test_direct_flow_with_route_exposure(tmp_path):
    root = write(tmp_path / "repo", {"app.py": """\
        import subprocess
        from flask import Flask, request
        from openai import OpenAI
        app = Flask(__name__)
        client = OpenAI()

        @app.route("/do")
        def do():
            q = request.args.get("q")
            r = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": q}])
            subprocess.run(r.choices[0].message.content, shell=True)
        """})
    res = scan(root, tmp_path)
    assert len(res.callsites) == 1 and res.callsites[0].model.name == "gpt-4o"
    (f,) = [f for f in res.flows if f.sink_class == "shell"]
    assert f.source_kind == "web_request" and f.E == 1.0 and f.priority == 0.5 and not f.gated
    assert [h.role for h in f.hops][0] == "source" and f.hops[-1].role == "sink"
    assert (tmp_path / "out" / "findings.json").exists()


def test_cross_file_wrapper_and_gated_variant(tmp_path):
    root = write(tmp_path / "repo", {
        "svc/llm.py": LLM,
        "svc/web.py": """\
            import subprocess
            from flask import Flask, request
            from svc.llm import ask
            app = Flask(__name__)
            ALLOWED = {"ls", "pwd"}

            def run_cmd(cmd):
                return subprocess.run(cmd, shell=True)

            @app.route("/open")
            def open_ep():
                cmd = ask(request.args.get("q"))
                return run_cmd(cmd)

            @app.route("/safe")
            def safe_ep():
                cmd = ask(request.args.get("q"))
                if cmd.split()[0] not in ALLOWED:
                    return "no"
                return run_cmd(cmd)
            """,
    })
    res = scan(root, tmp_path)
    shell = [f for f in res.flows if f.sink_class == "shell"]
    assert len(shell) == 2
    top, low = shell[0], shell[-1]
    assert not top.gated and top.priority == 0.5
    assert {"open_ep", "ask", "run_cmd"} <= {h.func_name for h in top.hops}
    assert low.gated and [g.gate for g in low.gates] == ["allowlist"] and low.priority < 0.05
    assert "safe_ep" in {h.func_name for h in low.hops}
    assert "ask" in res.wrappers
    assert len(res.passes) >= 2                     # stitching needed at least one extra pass


def test_tool_dispatch_reaching_shell(tmp_path):
    root = write(tmp_path / "repo", {"agent.py": """\
        import os
        import ollama

        def shell(command: str) -> str:
            return os.popen(command).read()

        def agent(task):
            r = ollama.chat(model="llama3.1", messages=[{"role": "user", "content": task}], tools=[shell])
            for call in r.message.tool_calls or []:
                {"shell": shell}[call.function.name](**call.function.arguments)
        """})
    res = scan(root, tmp_path)
    (cs,) = res.callsites
    assert [t.name for t in cs.tools] == ["shell"] and cs.model.kb_id == "llama3"
    tool_flows = [f for f in res.flows if f.channel == "tool_call"]
    assert tool_flows and tool_flows[0].sink_class == "shell"
    assert any(h.role == "tool" for h in tool_flows[0].hops)


def test_no_llm_no_flows(tmp_path):
    root = write(tmp_path / "repo", {"x.py": "import subprocess\n\ndef f(c):\n    subprocess.run(c, shell=True)\n"})
    res = scan(root, tmp_path)
    assert res.callsites == [] and res.flows == []


def test_semgrep_rule_snippets_pass():
    from app.llmflow.ruletest import run_rule_tests

    ok, out, names = run_rule_tests()
    assert ok, out[-3000:]
    assert {"callsite_openai", "callsite_anthropic", "callsite_ollama", "flows", "gates", "hygiene"} <= set(names)


def test_cli_scan_writes_mermaid_and_svg(tmp_path):
    from typer.testing import CliRunner

    from app.cli import cli

    root = write(tmp_path / "repo", {"svc/llm.py": LLM, "svc/run.py": """\
        import os
        from svc.llm import ask

        def main():
            os.system(ask(input("task: ")))
        """})
    out = tmp_path / "o"
    r = CliRunner().invoke(cli, ["llmflow", "scan", str(root), "--out", str(out), "--mermaid", str(out / "g.md"),
                                 "--svg", str(out / "r.svg")])
    assert r.exit_code == 0, r.output
    md = (out / "g.md").read_text(encoding="utf-8")
    assert "```mermaid" in md and "flowchart LR" in md and ":::sink" in md
    assert (out / "r.svg").read_text(encoding="utf-8").startswith("<svg")
