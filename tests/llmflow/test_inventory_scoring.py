"""Inventory model/tool resolution, KB matching, gates and ranking (no Semgrep needed)."""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

import pytest

from app.llmflow.astutil import SourceCache, params
from app.llmflow.catalog import load_catalog
from app.llmflow.gates import exposure, gates_on_path
from app.llmflow.inventory import RepoConfig, Resolver
from app.llmflow.kb import match_model, r_value
from app.llmflow.models import Flow, GateHit, Hop
from app.llmflow.rank import rank


@pytest.fixture(scope="module")
def cat():
    return load_catalog()


def _resolver(tmp_path: Path, files: dict[str, str]) -> tuple[Resolver, SourceCache]:
    for name, body in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body), encoding="utf-8")
    src = SourceCache(tmp_path)
    return Resolver(src, RepoConfig(tmp_path)), src


def _model(res: Resolver, src: SourceCache, rel: str, line: int):
    call = src.call_at(rel, line, name="create")
    return res.model(rel, call, "model", None)


def test_model_literal_constant_env_default_and_env_file(tmp_path):
    res, src = _resolver(tmp_path, {
        "a.py": """\
            import os
            MODEL = "gpt-4o"
            FALLBACK = os.getenv("LLM_MODEL", "gpt-4o-mini")
            KEYED = os.environ["CHAT_MODEL"]
            def f(c, m):
                c.chat.completions.create(model="claude-3-5-sonnet-latest", messages=m)
                c.chat.completions.create(model=MODEL, messages=m)
                c.chat.completions.create(model=FALLBACK, messages=m)
                c.chat.completions.create(model=KEYED, messages=m)
            """,
        ".env.example": "CHAT_MODEL=llama3.1:8b\n",
    })
    assert (_model(res, src, "a.py", 6).name, _model(res, src, "a.py", 6).how) == ("claude-3-5-sonnet-latest", "literal")
    assert (_model(res, src, "a.py", 7).name, _model(res, src, "a.py", 7).how) == ("gpt-4o", "constant")
    m = _model(res, src, "a.py", 8)
    assert (m.name, m.how, m.detail) == ("gpt-4o-mini", "env-default", "LLM_MODEL")
    m = _model(res, src, "a.py", 9)
    assert (m.name, m.how) == ("llama3.1:8b", "env-file")


def test_model_from_self_attr_param_default_and_config(tmp_path):
    res, src = _resolver(tmp_path, {
        "b.py": """\
            class Bot:
                def __init__(self, config=None):
                    self.model = (config or {}).get("model", "qwen2.5")
                def ask(self, c, m):
                    return c.chat.completions.create(model=self.model, messages=m)
            def g(c, m, model="gpt-4o"):
                return c.chat.completions.create(model=model, messages=m)
            def h(c, m, settings):
                return c.chat.completions.create(model=settings.llm, messages=m)
            """,
        "config/settings.yaml": "ai:\n  model: nvidia/nemotron\n",
    })
    m = _model(res, src, "b.py", 5)
    assert (m.name, m.how) == ("qwen2.5", "dict-default")
    m = _model(res, src, "b.py", 7)
    assert (m.name, m.how) == ("gpt-4o", "param-default")
    m = _model(res, src, "b.py", 9)
    assert m.name is None and m.how == "unknown"           # attribute of an unknown object


def test_tools_from_openai_dicts_and_dispatch_dict(tmp_path):
    res, src = _resolver(tmp_path, {
        "agent.py": """\
            import subprocess
            def run_shell(command):
                return subprocess.run(command, shell=True)
            def search(q, limit=5):
                return []
            TOOLS = [
                {"type": "function", "function": {"name": "shell", "parameters": {}}},
                {"type": "function", "function": {"name": "search", "parameters": {}}},
            ]
            DISPATCH = {"shell": run_shell, "search": search}
            def loop(client, msgs):
                return client.chat.completions.create(model="gpt-4o", messages=msgs, tools=TOOLS)
            """,
    })
    call = src.call_at("agent.py", 12, name="create")
    tools = {t.name: t for t in res.tools("agent.py", call, "tools")}
    assert tools["shell"].func_name == "run_shell" and tools["shell"].params == ["command"]
    assert tools["search"].func_name == "search" and tools["search"].params == ["q", "limit"]


def test_tools_as_python_functions_ollama_style(tmp_path):
    res, src = _resolver(tmp_path, {
        "o.py": """\
            import ollama
            def add(a: int, b: int) -> int:
                return a + b
            def go(msgs):
                return ollama.chat(model="llama3.1", messages=msgs, tools=[add])
            """,
    })
    call = src.call_at("o.py", 5, name="chat")
    (t,) = res.tools("o.py", call, "tools")
    assert (t.name, t.func_name, t.params) == ("add", "add", ["a", "b"])


def test_params_skip_self():
    fn = ast.parse("class A:\n    def m(self, a, *rest, k=1, **kw): pass").body[0].body[0]
    ps = params(fn)
    assert [(p.name, p.pos, p.kind) for p in ps] == [("a", 0, "positional"), ("rest", None, "vararg"),
                                                     ("k", None, "kwonly"), ("kw", None, "kwarg")]


def test_kb_matching_and_r_clamp(cat):
    assert match_model(cat.kb, "gpt-4o-mini-2024-07-18").id == "gpt-4o-mini"
    assert match_model(cat.kb, "gpt-4o").id == "gpt-4o"
    assert match_model(cat.kb, "llama3.1:8b").id == "llama3"
    assert match_model(cat.kb, "claude-3-5-sonnet-latest").id == "claude-sonnet"
    assert match_model(cat.kb, "mistral-large") is None
    r, kb_id = r_value(cat.kb, "unknown-model", "chat")
    assert (r, kb_id) == (0.5, None)
    assert cat.kb.defaults.min <= r_value(cat.kb, "gpt-4o", "tool_call")[0] <= cat.kb.defaults.max


def _hop(role, line, func="m::f@1", label="", code=""):
    return Hop(file="m.py", line=line, func=func, func_name="f", role=role, label=label, code=code)


def test_gate_must_be_after_llm_and_mention_the_value(cat):
    hops = [_hop("llm", 5, code="r = client.chat.completions.create()"),
            _hop("sink", 20, label="shell: cmd", code="subprocess.run(cmd, shell=True)")]
    allow = GateHit("allowlist", "deterministic", "allowlist", 0.05, "m.py", 10, "m::f@1", var="cmd.split()[0]")
    before = GateHit("allowlist", "deterministic", "allowlist", 0.05, "m.py", 3, "m::f@1", var="cmd")
    unrelated = GateHit("allowlist", "deterministic", "allowlist", 0.05, "m.py", 11, "m::f@1", var="user_role")
    escape = GateHit("html-escape", "deterministic", "html escaping", 0.05, "m.py", 12, "m::f@1", var="cmd")
    confirm = GateHit("human-confirm", "confirmation", "confirm", 0.3, "m.py", 15, "m::f@1")
    found = gates_on_path(cat, hops, "shell", [allow, before, unrelated, escape, confirm])
    assert {(g.gate, g.line) for g in found} == {("allowlist", 10), ("human-confirm", 15)}
    assert exposure(1.0, found) == 0.05
    assert exposure(0.5, []) == 0.5


def test_loop_carried_gate_counts_only_inside_the_loop(cat):
    """REPL shape: the answer arrives at line 66, the next iteration asks at 48 and runs it at 58."""
    repl = "m::Repl.handle@24"
    hops = [_hop("llm", 5, func="m::Base.handle@3"),
            _hop("call", 66, func=repl, code="answer = super().handle(prompt)"),
            _hop("call", 58, func=repl, label="", code="run_command(answer)"),
            _hop("sink", 90, func="m::run_command@88", label="shell: cmd", code="os.system(cmd)")]
    ask = GateHit("human-confirm", "confirmation", "confirm", 0.3, "m.py", 48, repl)
    before_loop = GateHit("human-confirm", "confirmation", "confirm", 0.3, "m.py", 40, repl)
    loops = lambda file, a, b: (47, 66)                   # noqa: E731 — loop body spans lines 47..66
    assert gates_on_path(cat, hops, "shell", [ask, before_loop], loops=loops) == [ask]
    assert gates_on_path(cat, hops, "shell", [ask, before_loop]) == []            # no loop info: no window
    assert gates_on_path(cat, hops, "shell", [ask], loops=lambda f, a, b: None) == []


def test_enclosing_loop(tmp_path):
    (tmp_path / "r.py").write_text(textwrap.dedent("""\
        def f():
            x = 1
            while True:
                a = input()
                for i in range(3):
                    print(i)
                b = a
        """), encoding="utf-8")
    src = SourceCache(tmp_path)
    assert src.enclosing_loop("r.py", 4, 7) == (4, 7)
    assert src.enclosing_loop("r.py", 6, 6) == (6, 6)
    assert src.enclosing_loop("r.py", 2, 4) is None


def test_rank_by_priority_and_by_s():
    def flow(S, E, R, cls):
        f = Flow(id="", sink_class=cls, sink_title=cls, cwe="", channel="chat", hops=[_hop("sink", 1)],
                 callsite=None, model=None, source_kind="unknown", source_title="")
        f.S, f.E, f.R = S, E, R
        return f
    flows = rank([flow(1.0, 0.05, 0.5, "shell"), flow(0.5, 1.0, 0.5, "html"), flow(0.9, 1.0, 0.5, "sql")])
    assert [f.sink_class for f in flows] == ["sql", "html", "shell"]
    assert {f.sink_class: f.rank_by_S for f in flows} == {"shell": 1, "sql": 2, "html": 3}
    assert flows[0].priority == 0.45
