"""Catalog → Semgrep rules (WP1).

Rule families (rule ids are stable so `semgrep --test` annotations can refer to them):

  llmflow.callsite.<call>      search: an SDK call site (inventory)
  llmflow.o2s.<target>         taint: LLM output (SDK call or a known wrapper) → target
  llmflow.i2p.<kind>.<target>  taint: untrusted source of <kind> → prompt / prompt-wrapper argument
  llmflow.par.<target>         taint: a function parameter → target (fragments for stitching)
  llmflow.gate.<gate>          search: gate patterns

Semgrep CE gives no dataflow traces without a login, so taint rules pass what we need through the
message: `taint_unify_mvars` lets the message reference source metavariables. Source-side
metavariables are renamed to an `$LS_` prefix so they never unify with sink-side ones by accident.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from app.llmflow.catalog import Catalog, Pattern, SdkCall, SinkClass
from app.llmflow.models import Target

MVAR = re.compile(r"\$(\.\.\.)?([A-Z_][A-Z0-9_]*)")
PARAM_EXCLUDE = r"^(?!(self|cls)\b)(?!\*\*)"     # parameters that can carry data into a function
GENERIC_NAMES = {
    # names too generic to use as wrapper sources/sinks: matching `$O.get(...)` everywhere is noise
    "get", "run", "call", "invoke", "execute", "read", "write", "format", "join", "append", "update",
    "send", "post", "put", "open", "close", "main", "load", "loads", "dump", "dumps", "parse",
    "apply", "map", "filter", "__call__", "__init__", "create", "query",
    "search", "request", "fetch", "print", "str", "repr", "copy", "items", "keys", "values", "split",
    "strip", "replace", "lower", "upper", "encode", "decode", "next", "set", "add", "remove", "pop",
}

# ------------------------------------------------------------------------------------------ helpers


def rename_mvars(text: str, prefix: str = "LS_", keep: frozenset[str] = frozenset({"X", "_"})) -> str:
    def sub(m: re.Match) -> str:
        dots, name = m.group(1) or "", m.group(2)
        if name in keep or name.startswith("_") and len(name) == 1:
            return m.group(0)
        return f"${dots}{prefix}{name}"
    return MVAR.sub(sub, text)


def _regex_items(regex: dict[str, str], rename: bool) -> list[dict]:
    out = []
    for mv, rx in regex.items():
        mv = rename_mvars(mv) if rename else mv
        out.append({"metavariable-regex": {"metavariable": mv, "regex": rx}})
    return out


def _import_inside(modules: list[str]) -> dict:
    alts = []
    for m in modules:
        alts.append({"pattern-inside": f"import {m}\n...\n"})
        alts.append({"pattern-inside": f"from {m} import $LS_IMP\n...\n"})
        alts.append({"pattern-inside": f"from {m}.$LS_SUB import $LS_IMP\n...\n"})
    return {"pattern-either": alts}


def _call_args(call: SdkCall, extra: str | None = None) -> str:
    """Argument list text for a call pattern; `extra` is one more argument such as `messages=$X`."""
    kws = [f"{k}=$_K{i}" for i, k in enumerate(call.require_kwargs) if not (extra and extra.startswith(k + "="))]
    parts = ["..."]
    if extra:
        parts.append(extra)
    parts += kws
    parts.append("...")
    return ", ".join(parts) if (extra or kws) else "..."


def _with_constraints(call: SdkCall, pattern: str, focus: str | None = None, rename: bool = False) -> dict:
    items: list[dict] = []
    if call.inside_import:
        either = _import_inside(call.inside_import)
        if call.receiver_regex:
            # e.g. `ollama = __import__("ollama")` inside a method: accept a receiver named like the SDK
            bare = f"{call.callee}(...)"
            either["pattern-either"].append({"patterns": [
                {"pattern": rename_mvars(bare) if rename else bare},
                {"metavariable-regex": {"metavariable": "$LS_C" if rename else "$C", "regex": call.receiver_regex}},
            ]})
        items.append(either)
    items.append({"pattern": rename_mvars(pattern) if rename else pattern})
    for ex in call.exclude:
        # own metavariable names: `$C` here must not be bound to the `$C` of the positive pattern
        items.append({"pattern-not": rename_mvars(f"{ex}(...)", prefix="NOT_")})
    if focus:
        items.append({"focus-metavariable": focus})
    return {"patterns": items} if len(items) > 1 else items[0]


def sdk_call_pattern(call: SdkCall, rename: bool = False) -> dict:
    return _with_constraints(call, f"{call.callee}({_call_args(call)})", rename=rename)


def prompt_sinks(cat: Catalog) -> list[dict]:
    out = []
    for _sdk, call in cat.sdk_calls():
        for arg in call.prompt_args:
            out.append(_with_constraints(call, f"{call.callee}({_call_args(call, f'{arg}=$X')})", "$X"))
        for pos in call.prompt_pos:
            lead = ", ".join(["$_P"] * pos)
            args = f"{lead}, $X, ..." if lead else "$X, ..."
            out.append(_with_constraints(call, f"{call.callee}({args})", "$X"))
    return out


def _pattern_entry(p: Pattern, focus: str | None, rename: bool) -> dict:
    pat = rename_mvars(p.pattern) if rename else p.pattern
    items: list[dict] = [{"pattern": pat}]
    for n in p.not_:
        items.append({"pattern-not": rename_mvars(n) if rename else n})
    items += _regex_items(p.regex, rename)
    if focus:
        items.append({"focus-metavariable": focus})
    return {"patterns": items} if len(items) > 1 else items[0]


def sink_class_sinks(sc: SinkClass) -> list[dict]:
    return [_pattern_entry(p, "$X", rename=False) for p in sc.patterns]


def fn_target_sinks(t: Target) -> list[dict]:
    """Sink patterns for an argument of a wrapper function, called as `f(...)` or `$O.f(...)`."""
    pats = []
    for callee in (t.name, f"$O.{t.name}"):
        if t.pos is not None:
            lead = ", ".join(["$_A"] * t.pos)
            pats.append(f"{callee}({lead + ', ' if lead else ''}$X, ...)")
        if t.param:
            pats.append(f"{callee}(..., {t.param}=$X, ...)")
    return [{"patterns": [{"pattern": p}, {"focus-metavariable": "$X"}]} for p in pats]


def target_sinks(cat: Catalog, t: Target) -> list[dict]:
    if t.kind == "sink":
        return sink_class_sinks(cat.sinks.classes[t.name])
    if t.kind == "return":
        # generators that stream the completion (`yield chunk.choices[0].delta.content`) count as returning it
        return [{"patterns": [{"pattern": "return $X"}, {"focus-metavariable": "$X"}]},
                {"patterns": [{"pattern": "yield $X"}, {"focus-metavariable": "$X"}]}]
    if t.kind == "prompt":
        return prompt_sinks(cat)
    return fn_target_sinks(t)


def wrapper_sources(names: list[str]) -> list[dict]:
    names = sorted({n for n in names if n not in GENERIC_NAMES})
    if not names:
        return []
    rx = "^(" + "|".join(re.escape(n) for n in names) + ")$"
    return [
        {"patterns": [{"pattern": "$LS_FN(...)"},
                      {"metavariable-regex": {"metavariable": "$LS_FN", "regex": rx}}]},
        {"patterns": [{"pattern": "$LS_O.$LS_FN(...)"},
                      {"metavariable-regex": {"metavariable": "$LS_FN", "regex": rx}}]},
    ]


PROPAGATORS = [
    {"pattern": "$TO.append($FROM)", "from": "$FROM", "to": "$TO"},
    {"pattern": "$TO.extend($FROM)", "from": "$FROM", "to": "$TO"},
    {"pattern": "$TO.insert($I, $FROM)", "from": "$FROM", "to": "$TO"},
    {"pattern": "$TO.update($FROM)", "from": "$FROM", "to": "$TO"},
    {"pattern": "$TO.write($FROM)", "from": "$FROM", "to": "$TO"},
    {"pattern": "$TO[$K] = $FROM", "from": "$FROM", "to": "$TO"},
]


def _taint_rule(rid: str, sources: list[dict], sinks: list[dict], message: str, meta: dict) -> dict:
    return {
        "id": rid,
        "mode": "taint",
        "languages": ["python"],
        "severity": "WARNING",
        "message": message,
        "metadata": meta,
        "options": {"taint_unify_mvars": True},
        "pattern-sources": sources,
        "pattern-propagators": PROPAGATORS,
        "pattern-sinks": sinks,
    }


def _target_meta(t: Target) -> dict:
    d = {"target_kind": t.kind, "target_name": t.name, "target_param": t.param,
         "target_pos": t.pos, "target_role": t.role, "target_tid": t.tid}
    return {k: v for k, v in d.items() if v is not None}     # semgrep rejects null values


# ------------------------------------------------------------------------------------------ families


def callsite_rules(cat: Catalog) -> list[dict]:
    rules = []
    for sdk, call in cat.sdk_calls():
        p = sdk_call_pattern(call)
        body = p if "patterns" in p else {"pattern": p["pattern"]}
        rules.append({"id": f"llmflow.callsite.{call.id}", "languages": ["python"], "severity": "INFO",
                      "message": f"{sdk.sdk} call site", "metadata": {"family": "callsite", "call": call.id,
                                                                     "sdk": sdk.sdk}, **body})
    return rules


def o2s_rule(cat: Catalog, t: Target, wrappers: list[str]) -> dict:
    sources = [sdk_call_pattern(c, rename=True) for _s, c in cat.sdk_calls()] + wrapper_sources(wrappers)
    # `exact`: only the call's result is LLM output, not its arguments (Semgrep taints sub-expressions of a
    # source by default, which would make the prompt passed *into* the call look like model output)
    sources = [{**s, "exact": True} for s in sources]
    return _taint_rule(f"llmflow.o2s.{t.tid}", sources, target_sinks(cat, t),
                       "LLM output reaches a sink @@FN=$LS_FN@@X=$X@@",
                       {"family": "o2s", **_target_meta(t)})


def i2p_rules(cat: Catalog, t: Target) -> list[dict]:
    rules = []
    for kind, sk in cat.sources.kinds.items():
        sources = [_pattern_entry(p, None, rename=True) for p in sk.patterns]
        rules.append(_taint_rule(f"llmflow.i2p.{kind}.{t.tid}", sources, target_sinks(cat, t),
                                 f"untrusted {kind} reaches a prompt @@X=$X@@",
                                 {"family": "i2p", "source_kind": kind, **_target_meta(t)}))
    return rules


def par_rule(cat: Catalog, t: Target) -> dict:
    source = {"patterns": [
        {"pattern-inside": "def $LS_F(..., $LS_P, ...):\n  ...\n"},
        {"focus-metavariable": "$LS_P"},
        {"metavariable-regex": {"metavariable": "$LS_P", "regex": PARAM_EXCLUDE}},
    ]}
    return _taint_rule(f"llmflow.par.{t.tid}", [source], target_sinks(cat, t),
                       "parameter reaches a target @@F=$LS_F@@P=$LS_P@@X=$X@@",
                       {"family": "par", **_target_meta(t)})


def gate_rules(cat: Catalog) -> list[dict]:
    rules = []
    for g in cat.gates.gates:
        alts = [{"pattern": p} for p in g.patterns]
        body: dict = {"pattern-either": alts}
        if g.regex:
            body = {"patterns": [body, *_regex_items(g.regex, rename=False)]}
        rules.append({"id": f"llmflow.gate.{g.id}", "languages": ["python"], "severity": "INFO",
                      "message": f"gate {g.id} @@V=$V@@", "metadata": {"family": "gate", "gate": g.id},
                      **body})
    return rules


def source_rules(cat: Catalog) -> list[dict]:
    """Search rules for untrusted sources: taint results carry no trace, so these locate the source line."""
    rules = []
    for kind, sk in cat.sources.kinds.items():
        alts = [_pattern_entry(p, None, rename=False) for p in sk.patterns]
        rules.append({"id": f"llmflow.src.{kind}", "languages": ["python"], "severity": "INFO",
                      "message": f"untrusted source {kind}", "metadata": {"family": "src", "source_kind": kind},
                      "pattern-either": alts})
    return rules


def hygiene_rules(cat: Catalog) -> list[dict]:
    data = yaml.safe_load(cat.hygiene_path.read_text(encoding="utf-8")) or {}
    rules = data.get("rules", [])
    for r in rules:
        r.setdefault("metadata", {})["family"] = "hygiene"
    return rules


# ------------------------------------------------------------------------------------------ rule sets


def base_targets(cat: Catalog, extra_sinks: set[str] | None = None) -> list[Target]:
    return [Target("sink", name) for name in cat.sinks.enabled(extra_sinks)]


def static_rules(cat: Catalog, extra_sinks: set[str] | None = None) -> list[dict]:
    """Pass 0: call sites, gates, hygiene and the taint rules that need no discovered wrappers."""
    sinks = base_targets(cat, extra_sinks)
    rules = callsite_rules(cat) + gate_rules(cat) + source_rules(cat) + hygiene_rules(cat)
    for t in sinks + [Target("return", "return")]:
        rules.append(o2s_rule(cat, t, []))
    rules += i2p_rules(cat, Target("prompt", "prompt"))
    for t in sinks + [Target("prompt", "prompt")]:
        rules.append(par_rule(cat, t))
    return rules


def pass_rules(cat: Catalog, wrappers: list[str], all_s_targets: list[Target], new_fn_targets: list[Target],
               new_wrappers: bool, extra_sinks: set[str] | None = None) -> list[dict]:
    """Pass k ≥ 1: rules that involve wrappers discovered so far.

    - if the wrapper set grew: o2s from all known wrappers to base sinks, `return` and every S target
      (a new wrapper can now reach an old S function); otherwise o2s only to the new S targets
    - i2p to new I targets, par to all new fn targets
    """
    rules: list[dict] = []
    new_s = [t for t in new_fn_targets if t.role == "S"]
    o2s_targets = (base_targets(cat, extra_sinks) + [Target("return", "return")] + all_s_targets
                   if new_wrappers else new_s)
    seen: set[str] = set()
    for t in o2s_targets:
        if t.tid not in seen:
            seen.add(t.tid)
            rules.append(o2s_rule(cat, t, wrappers))
    for t in new_fn_targets:
        if t.role == "I":
            rules += i2p_rules(cat, t)
        rules.append(par_rule(cat, t))
    return rules


class _NoAliasDumper(yaml.SafeDumper):
    """Semgrep's YAML reader does not resolve anchors/aliases, so never emit them."""

    def ignore_aliases(self, data) -> bool:
        return True


def dump_rules(rules: list[dict]) -> str:
    return yaml.dump({"rules": rules}, Dumper=_NoAliasDumper, sort_keys=False, allow_unicode=True, width=200)


def write_rules(rules: list[dict], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dump_rules(rules), encoding="utf-8")
    return path
