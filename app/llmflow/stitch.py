"""Cross-function stitching (WP6).

Semgrep CE taint stays inside one function, so each pass records per-function *fragments*:

  R(f)        f returns LLM output                       (o2s → return)
  S(f, p)     parameter p of f reaches a dangerous sink    (par → sink / S-target)
  I(f, p)     parameter p of f reaches a prompt            (par → prompt / I-target)

and the next pass turns them into rules: calls to R functions become LLM-output sources, arguments of S/I
functions become sinks. Passes repeat until no new fragment appears or `max_depth` is reached. Names are
resolved with the analyzer's code index (app/context): a name defined in several places is kept but the
edge is marked approximate; names with more than `MAX_TARGETS` definitions or generic names are dropped.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field

from app.context.callgraph import MAX_TARGETS
from app.context.index import FuncInfo, SnapshotIndex
from app.llmflow.astutil import SourceCache, clean_param, params
from app.llmflow.catalog import Catalog
from app.llmflow.models import CallSite, Hop, Match, Target
from app.llmflow.rulegen import GENERIC_NAMES

MAX_HOPS = 10
IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
ENTRY_KINDS_WEB = {"route", "django_view", "class_view_method", "lambda", "decorated:api_view",
                   "decorated:action", "decorated:view_config", "decorated:expose"}
ENTRY_KINDS_CLI = {"cli_main", "decorated:command", "decorated:group", "decorated:click.command"}


@dataclass
class RFact:
    func: str | None
    name: str
    callsite: str | None
    chain: list[Hop]                 # LLM call … → return in this function
    channel: str = "chat"


@dataclass
class SFact:
    func: str | None
    name: str
    param: str
    pos: int | None
    sink_class: str
    chain: list[Hop]                 # entry of this function … → sink


@dataclass
class IFact:
    func: str | None
    name: str
    param: str
    pos: int | None
    callsite: str | None
    chain: list[Hop]                 # entry of this function … → prompt


@dataclass
class RawFlow:
    sink_class: str
    callsite: str | None
    channel: str
    hops: list[Hop]
    via_tool: str | None = None


@dataclass
class Exposure:
    callsite: str
    kind: str
    E: float
    title: str
    chain: list[Hop]                 # source … → prompt


@dataclass
class Facts:
    R: dict[str, list[RFact]] = field(default_factory=lambda: defaultdict(list))
    S: dict[tuple[str, str], list[SFact]] = field(default_factory=lambda: defaultdict(list))
    I: dict[tuple[str, str], list[IFact]] = field(default_factory=lambda: defaultdict(list))
    flows: list[RawFlow] = field(default_factory=list)
    exposures: list[Exposure] = field(default_factory=list)
    _keys: set = field(default_factory=set)

    def add(self, key: tuple) -> bool:
        if key in self._keys:
            return False
        self._keys.add(key)
        return True


def _idents(text: str) -> set[str]:
    return {t for t in IDENT.findall(text or "") if t not in ("self", "cls", "str", "int", "None", "True", "False")}


class Stitcher:
    def __init__(self, cat: Catalog, idx: SnapshotIndex, src: SourceCache, callsites: list[CallSite],
                 entrypoints: dict[str, str]):
        self.cat = cat
        self.idx = idx
        self.src = src
        self.callsites = callsites
        self.cs_by_id = {c.id: c for c in callsites}
        self.entrypoints = entrypoints
        self.facts = Facts()
        self.sources: list[Match] = []
        self.defs: dict[str, list[FuncInfo]] = defaultdict(list)
        for fn in idx.all_functions():
            self.defs[fn.simple_name].append(fn)
        self.tool_funcs: set[str] = {t.func_name for c in callsites for t in c.tools if t.func_name}
        self._targets_done: set[str] = set()
        self.aliases = self._find_aliases()          # alias name -> {function names}
        self.alias_of: dict[str, set[str]] = defaultdict(set)
        for a, reals in self.aliases.items():
            for r in reals:
                self.alias_of[r].add(a)

    def _find_aliases(self) -> dict[str, set[str]]:
        """`self.run_sql = run_sql_sqlite` / `handler = process`: calls through the alias reach the function."""
        import ast

        out: dict[str, set[str]] = defaultdict(set)
        for rel in self.idx.files:
            tree = self.src.tree(rel)
            if tree is None:
                continue
            local = {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.value, ast.Name)
                        and node.value.id in local):
                    continue
                t = node.targets[0]
                alias = t.attr if isinstance(t, ast.Attribute) else t.id if isinstance(t, ast.Name) else None
                if alias and alias != node.value.id:
                    out[alias].add(node.value.id)
        return out

    # ------------------------------------------------------------------ helpers

    def usable_name(self, name: str) -> bool:
        if not name or name in GENERIC_NAMES or name.startswith("__"):
            return False
        defs = self.defs.get(name, [])
        if 0 < len(defs) <= MAX_TARGETS or name in self.aliases:
            return True
        # one method name implemented by many classes (an interface, e.g. one `submit_prompt` per LLM backend)
        return 0 < len(defs) <= 40 and all("." in d.name for d in defs)

    def ambiguous(self, name: str) -> bool:
        return len(self.defs.get(name, [])) > 1 or name in self.aliases

    def consistent_pos(self, name: str, param: str, pos: int | None) -> int | None:
        """Positional index to match calls by, or None (keyword only) when other functions with the same name
        (overrides, same-named helpers) have a different parameter at that position."""
        if pos is None:
            return None
        for d in self.defs.get(name, []):
            fdef = self.src.function_def(d.file, d.simple_name, d.start)
            if fdef is None:
                continue
            ps = [p for p in params(fdef) if p.pos is not None]
            if pos >= len(ps) or ps[pos].name != param:
                if not any(p.kind == "vararg" for p in params(fdef)):
                    return None
        return pos

    @staticmethod
    def method_class(func_id: str | None) -> str | None:
        """`pkg/m.py::Outer.PythonREPL.run@12` → `PythonREPL` (None for module-level functions)."""
        if not func_id or "::" not in func_id:
            return None
        qual = func_id.split("::", 1)[1].rsplit("@", 1)[0]
        parts = qual.split(".")
        return parts[-2] if len(parts) >= 2 and not parts[-2].startswith("<") else None

    def s_facts(self, name: str, param: str | None, cls: str | None = None) -> list[SFact]:
        out = list(self.facts.S.get((name, param), []))
        for real in sorted(self.aliases.get(name, ())):
            out += self.facts.S.get((real, param), [])
        return [f for f in out if cls is None or self.method_class(f.func) == cls]

    def i_facts(self, name: str, param: str | None, cls: str | None = None) -> list[IFact]:
        out = list(self.facts.I.get((name, param), []))
        for real in sorted(self.aliases.get(name, ())):
            out += self.facts.I.get((real, param), [])
        return [f for f in out if cls is None or self.method_class(f.func) == cls]

    def targets_for(self, name: str, param: str, facts: list, role: str) -> list[Target]:
        """Targets for calls into a fragment's function: by name (and aliases) when the name is usable, else —
        for methods with generic names such as `run` — one class-qualified target per defining class."""
        if self.usable_name(name):
            pos = self.consistent_pos(name, param, facts[0].pos)
            return [Target("fn", n, param, pos, role) for n in [name, *sorted(self.alias_of.get(name, ()))]]
        if name.startswith("__"):
            return []
        out, seen = [], set()
        for f in facts:
            cls = self.method_class(f.func)
            if cls and cls not in seen:
                seen.add(cls)
                out.append(Target("fn", name, param, f.pos, role, cls))
        return out

    def func_at(self, file: str, line: int) -> FuncInfo | None:
        return self.idx.function_at(file, line)

    def hop(self, file: str, line: int, role: str, label: str = "", approx: bool = False) -> Hop:
        fn = self.func_at(file, line)
        return Hop(file=file, line=line, func=fn.id if fn else None, func_name=fn.name if fn else None,
                   role=role, label=label, code=self.src.line(file, line), approx=approx)

    def callsite_for(self, file: str, line: int) -> CallSite | None:
        """The LLM call site feeding a match at (file, line): same function, last one at or before the line."""
        fn = self.func_at(file, line)
        same = [c for c in self.callsites if c.file == file and (c.func == (fn.id if fn else None))]
        before = [c for c in same if c.line <= line]
        if before:
            return max(before, key=lambda c: c.line)
        if same:
            return min(same, key=lambda c: c.line)
        in_file = [c for c in self.callsites if c.file == file and c.line <= line]
        return max(in_file, key=lambda c: c.line) if in_file else None

    def llm_hop(self, cs: CallSite) -> Hop:
        label = f"{cs.sdk} · {cs.model.name or 'model?'}"
        return self.hop(cs.file, cs.line, "llm", label)

    def call_line(self, file: str, fn: FuncInfo | None, name: str, upto: int, value: str = "") -> int:
        """Line in fn where `name(` is called: wrapper calls have no trace, so find them by text.

        The nearest call at or before `upto` wins; if there is none, the nearest one after it (a value produced
        later in a loop body and used in the next iteration, e.g. a REPL). Calls whose result is assigned to a
        variable of the tainted `value` are preferred over other calls of the same name; `def name(` lines
        never count.
        """
        if fn is None:
            return upto
        rx = re.compile(rf"\b{re.escape(name)}\s*\(")
        defn = re.compile(rf"^\s*(async\s+)?def\s+{re.escape(name)}\s*\(")
        wanted = _idents(value)
        assign = re.compile(r"^\s*([A-Za-z_][\w.,\s\[\]]*?)\s*(?::[^=]+)?=(?!=)")

        def is_call(n: int, assigned: bool) -> bool:
            text = self.src.line(file, n)
            if not rx.search(text) or defn.match(text):
                return False
            if not assigned:
                return True
            m = assign.match(text)
            return bool(m and _idents(m.group(1)) & wanted)

        order = list(range(upto, fn.start - 1, -1)) + list(range(upto + 1, fn.end + 1))
        for assigned in ([True, False] if wanted else [False]):
            for n in order:
                if is_call(n, assigned):
                    return n
        return upto

    def param_info(self, file: str, fname: str, line: int, raw: str) -> tuple[str, int | None]:
        p = clean_param(raw)
        fdef = self.src.function_def(file, fname, line)
        if fdef is not None:
            for prm in params(fdef):
                if prm.name == p:
                    return p, prm.pos
        return p, None

    def origin(self, m: Match) -> list[tuple[list[Hop], str | None, str]]:
        """[(chain up to and including this function's receipt of LLM output, callsite id, channel)]."""
        fn_name = m.fields.get("FN")
        if not fn_name:
            cs = self.callsite_for(m.file, m.line)
            return [([self.llm_hop(cs)], cs.id, cs.channel)] if cs else []
        out = []
        facts = self.facts.R.get(fn_name, [])
        here = self.func_at(m.file, m.line)
        approx = self.ambiguous(fn_name)
        for rf in facts[:8]:
            if here is not None and rf.func == here.id:
                continue                                    # recursion
            line = self.call_line(m.file, here, fn_name, m.line, m.fields.get("X") or "")
            h = self.hop(m.file, line, "call", f"{fn_name}(…) returns LLM output", approx=approx)
            out.append((rf.chain + [h], rf.callsite, rf.channel))
        return out

    # ------------------------------------------------------------------ fragment processing

    def process(self, matches: list[Match]) -> None:
        for m in matches:
            fam = m.family
            if fam == "src":
                self.sources.append(m)
        for m in matches:
            fam = m.family
            if fam == "o2s":
                self._o2s(m)
            elif fam == "par":
                self._par(m)
        for m in matches:
            if m.family == "i2p":
                self._i2p(m)

    def _target(self, m: Match) -> Target:
        md = m.meta
        return Target(md["target_kind"], md["target_name"], md.get("target_param"), md.get("target_pos"),
                      md.get("target_role"), md.get("target_cls"))

    def _o2s(self, m: Match) -> None:
        t = self._target(m)
        x = m.fields.get("X") or ""
        for chain, cs_id, channel in self.origin(m):
            if len(chain) >= MAX_HOPS:
                continue
            if t.kind == "sink":
                sink = self.hop(m.file, m.line, "sink", t.name)
                sink.label = f"{t.name}: {x[:60]}"
                self._flow(RawFlow(t.name, cs_id, channel, chain + [sink]))
            elif t.kind == "return":
                fn = self.func_at(m.file, m.line)
                if fn is None or fn.id in self.entrypoints:
                    continue                                # route handlers return responses, not LLM text
                if not (self.usable_name(fn.simple_name) or self.self_wrapper(fn)):
                    continue
                if not self.facts.add(("R", fn.id, cs_id)):
                    continue
                ret = self.hop(m.file, m.line, "wrapper", f"{fn.simple_name}() returns LLM output")
                self.facts.R[fn.simple_name].append(RFact(fn.id, fn.simple_name, cs_id, chain + [ret], channel))
            elif t.kind == "fn" and t.role == "S":
                approx = self.ambiguous(t.name)
                call = self.hop(m.file, m.line, "call", f"→ {t.name}({t.param}=…)", approx=approx)
                for sf in self.s_facts(t.name, t.param, t.cls)[:3]:
                    if len(chain) + len(sf.chain) + 1 > MAX_HOPS:
                        continue
                    self._flow(RawFlow(sf.sink_class, cs_id, channel, chain + [call] + sf.chain))

    def _par(self, m: Match) -> None:
        t = self._target(m)
        fname = m.fields.get("F")
        raw_p = m.fields.get("P")
        if not fname or not raw_p:
            return
        fn = self.func_at(m.file, m.line)
        fid = fn.id if fn else None
        param, pos = self.param_info(m.file, fname, m.line, raw_p)
        if t.kind == "fn" and t.name == fname:
            return                                          # direct recursion
        if t.kind == "sink":
            if not self.facts.add(("S", fid, param, t.name, m.line)):
                return
            sink = self.hop(m.file, m.line, "sink", f"{t.name}: {(m.fields.get('X') or '')[:60]}")
            self.facts.S[(fname, param)].append(SFact(fid, fname, param, pos, t.name, [sink]))
        elif t.kind == "prompt":
            cs = self.callsite_for(m.file, m.line)
            if cs is None or not self.facts.add(("I", fid, param, cs.id)):
                return
            self.facts.I[(fname, param)].append(IFact(fid, fname, param, pos, cs.id,
                                                      [self.hop(m.file, m.line, "prompt", f"prompt ← {param}")]))
        elif t.kind == "fn":
            approx = self.ambiguous(t.name)
            call = self.hop(m.file, m.line, "call", f"{param} → {t.name}({t.param}=…)", approx=approx)
            if t.role == "S":
                for sf in self.s_facts(t.name, t.param, t.cls)[:3]:
                    if len(sf.chain) + 1 > MAX_HOPS or not self.facts.add(("S", fid, param, sf.func, sf.sink_class)):
                        continue
                    self.facts.S[(fname, param)].append(
                        SFact(fid, fname, param, pos, sf.sink_class, [call] + sf.chain))
            else:
                for inf in self.i_facts(t.name, t.param, t.cls)[:3]:
                    if len(inf.chain) + 1 > MAX_HOPS or not self.facts.add(("I", fid, param, inf.callsite)):
                        continue
                    self.facts.I[(fname, param)].append(
                        IFact(fid, fname, param, pos, inf.callsite, [call] + inf.chain))

    def _source_hop(self, kind: str, file: str, line: int) -> Hop:
        fn = self.func_at(file, line)
        cands = [s for s in self.sources if s.file == file and s.meta.get("source_kind") == kind
                 and s.line <= line and (fn is None or fn.start <= s.line <= fn.end)]
        src_line = max(cands, key=lambda s: s.line).line if cands else (fn.start if fn else line)
        title = self.cat.sources.kinds[kind].title
        return self.hop(file, src_line, "source", title)

    def _i2p(self, m: Match) -> None:
        t = self._target(m)
        kind = m.meta.get("source_kind", "unknown")
        sk = self.cat.sources.kinds.get(kind)
        E = sk.E if sk else self.cat.sources.defaults.unknown
        title = sk.title if sk else kind
        src = self._source_hop(kind, m.file, m.line)
        if t.kind == "prompt":
            cs = self.callsite_for(m.file, m.line)
            if cs is None:
                return
            prompt = self.hop(m.file, m.line, "prompt", f"prompt ← {(m.fields.get('X') or '')[:50]}")
            self._expose(Exposure(cs.id, kind, E, title, [src, prompt]))
        elif t.kind == "fn" and t.role == "I":
            call = self.hop(m.file, m.line, "call", f"→ {t.name}({t.param}=…)", approx=self.ambiguous(t.name))
            for inf in self.i_facts(t.name, t.param, t.cls)[:3]:
                if inf.callsite:
                    self._expose(Exposure(inf.callsite, kind, E, title, [src, call] + inf.chain))

    def _expose(self, e: Exposure) -> None:
        if self.facts.add(("X", e.callsite, e.kind, e.chain[0].file, e.chain[0].line)):
            self.facts.exposures.append(e)

    def _flow(self, f: RawFlow) -> None:
        key = ("F", f.sink_class, f.sink_class and f.hops[-1].file, f.hops[-1].line, f.callsite, f.via_tool,
               tuple((h.file, h.line) for h in f.hops))
        if self.facts.add(key):
            self.facts.flows.append(f)

    # ------------------------------------------------------------------ after the fixpoint

    def entry_exposures(self) -> None:
        """Route handler parameters that reach a prompt (directly or through I-wrappers)."""
        d = self.cat.sources.defaults
        auth = re.compile(d.auth_markers)
        for (fname, param), facts in list(self.facts.I.items()):
            for inf in facts:
                kind = self.entrypoints.get(inf.func or "")
                if not kind or not inf.callsite:
                    continue
                fn = next((f for f in self.idx.all_functions() if f.id == inf.func), None)
                if kind in ENTRY_KINDS_WEB:
                    is_auth = bool(fn and auth.search(fn.header))
                    k, E = ("route_param_auth", d.route_param_auth) if is_auth else ("route_param", d.route_param)
                    title = "Route parameter (auth required)" if is_auth else "Route parameter"
                elif kind in ENTRY_KINDS_CLI:
                    k, E, title = "cli", self.cat.sources.kinds["cli"].E if "cli" in self.cat.sources.kinds else 0.5, \
                        "CLI argument"
                else:
                    continue
                src = self.hop(fn.file, fn.start, "source", f"{title}: {param}") if fn else inf.chain[0]
                self._expose(Exposure(inf.callsite, k, E, title, [src] + inf.chain))

    def tool_flows(self) -> None:
        """Parameters of tool functions are chosen by the model: S facts on them are LLM-output flows."""
        for cs in self.callsites:
            for tool in cs.tools:
                if not tool.func_name:
                    continue
                for p in tool.params:
                    for sf in self.facts.S.get((tool.func_name, p), [])[:3]:
                        th = Hop(file=tool.file or cs.file, line=tool.line or cs.line, func=tool.func,
                                 func_name=tool.func_name, role="tool",
                                 label=f"tool {tool.name}({p}) ← model",
                                 code=self.src.line(tool.file or cs.file, tool.line or cs.line))
                        self._flow(RawFlow(sf.sink_class, cs.id, "tool_call", [self.llm_hop(cs), th] + sf.chain,
                                           via_tool=tool.name))

    # ------------------------------------------------------------------ targets for the next pass

    @staticmethod
    def self_wrapper(fn: FuncInfo) -> bool:
        """A method with a generic name (`call`, `run`): usable as a wrapper through `self.<name>(...)` only."""
        return fn.simple_name in GENERIC_NAMES and not fn.simple_name.startswith("__") and "." in fn.name

    def wrapper_names(self) -> list[str]:
        return sorted(n for n, facts in self.facts.R.items()
                      if self.usable_name(n) or (n in GENERIC_NAMES and not n.startswith("__")
                                                 and any(self.method_class(f.func) for f in facts)))

    def new_fn_targets(self) -> list[Target]:
        out = []
        for role, table in (("S", self.facts.S), ("I", self.facts.I)):
            for (name, param), facts in table.items():
                if not facts:
                    continue
                for t in self.targets_for(name, param, facts, role):
                    if t.tid in self._targets_done:
                        continue
                    self._targets_done.add(t.tid)
                    out.append(t)
        return out

    def all_s_targets(self) -> list[Target]:
        out = []
        for (n, p), fs in self.facts.S.items():
            if fs:
                out += self.targets_for(n, p, fs, "S")
        return out


def gate_overlap(var: str | None, x: str) -> bool:
    if not var:
        return True
    return bool(_idents(var) & _idents(x))
