"""Catalog schema and rule generator (no Semgrep needed)."""

from __future__ import annotations

import pytest
import yaml

from app.llmflow.catalog import SinkClass, load_catalog
from app.llmflow.models import Target
from app.llmflow.rulegen import (dump_rules, fn_target_sinks, pass_rules, rename_mvars, static_rules,
                                 wrapper_sources)


@pytest.fixture(scope="module")
def cat():
    return load_catalog()


def test_catalog_loads_three_sdks(cat):
    assert {s.sdk for s in cat.sdks} == {"openai", "anthropic", "ollama"}
    ids = [c.id for _s, c in cat.sdk_calls()]
    assert len(ids) == len(set(ids))
    assert cat.sinks.classes["shell"].S == 1.0
    assert "text" not in cat.sinks.enabled()           # off by default
    assert "text" in cat.sinks.enabled({"text"})
    assert len(cat.gates.gates) >= 10
    assert len(cat.kb.models) == 5


def test_sink_patterns_must_bind_x():
    with pytest.raises(ValueError):
        SinkClass.model_validate({"S": 1, "cwe": "CWE-78", "title": "t", "patterns": [{"pattern": "os.system($Y)"}]})


def test_rename_mvars_keeps_x_and_anonymous():
    assert rename_mvars("$C.chat($X, $_, $...ARGS)") == "$LS_C.chat($X, $_, $...LS_ARGS)"


def test_static_rules_are_valid_yaml_without_aliases_or_nulls(cat):
    text = dump_rules(static_rules(cat))
    assert "&id" not in text and "*id" not in text
    data = yaml.safe_load(text)
    ids = [r["id"] for r in data["rules"]]
    assert len(ids) == len(set(ids))
    fams = {r["metadata"]["family"] for r in data["rules"]}
    assert {"callsite", "o2s", "i2p", "par", "gate", "src", "hygiene"} <= fams

    def no_null(o):
        if isinstance(o, dict):
            return all(v is not None and no_null(v) for v in o.values())
        if isinstance(o, list):
            return all(no_null(v) for v in o)
        return True
    assert no_null(data)


def test_taint_rules_unify_mvars_and_rename_source_side(cat):
    rules = {r["id"]: r for r in static_rules(cat)}
    o2s = rules["llmflow.o2s.sink.shell"]
    assert o2s["options"]["taint_unify_mvars"] is True
    src_text = yaml.safe_dump(o2s["pattern-sources"])
    assert "$C." not in src_text and "$LS_C." in src_text     # no accidental unification with sink $C
    assert "@@X=$X@@" in o2s["message"]


def test_exclusions_use_their_own_metavariables(cat):
    rule = {r["id"]: r for r in static_rules(cat)}["llmflow.callsite.openai.completions"]
    text = yaml.safe_dump(rule)
    assert "$NOT_C.chat.completions.create(...)" in text


def test_fn_target_sinks_cover_positional_and_keyword():
    pats = [p["patterns"][0]["pattern"] for p in fn_target_sinks(Target("fn", "run_cmd", "cmd", 1, "S"))]
    assert "run_cmd($_A, $X, ...)" in pats
    assert "$O.run_cmd(..., cmd=$X, ...)" in pats


def test_generic_wrapper_names_only_through_self():
    """`call`/`run` wrappers count only as `self.call(...)`, never as `anything.call(...)`."""
    (only_self,) = wrapper_sources(["call", "run"])
    assert only_self["patterns"][0] == {"pattern": "self.$LS_FN(...)"}
    src = wrapper_sources(["ask_llm", "call"])
    text = yaml.safe_dump(src)
    assert "^(ask_llm)$" in text and "^(call)$" in text
    assert [s["patterns"][0]["pattern"] for s in src] == ["$LS_FN(...)", "$LS_O.$LS_FN(...)", "self.$LS_FN(...)"]


def test_pass_rules_only_new_targets_when_wrappers_unchanged(cat):
    t = Target("fn", "run_cmd", "cmd", 0, "S")
    rules = pass_rules(cat, ["ask"], [t], [t], new_wrappers=False)
    ids = [r["id"] for r in rules]
    assert ids == ["llmflow.o2s.fn.S.run_cmd.cmd", "llmflow.par.fn.S.run_cmd.cmd"]
    rules = pass_rules(cat, ["ask"], [t], [], new_wrappers=True)
    assert "llmflow.o2s.sink.shell" in [r["id"] for r in rules]
