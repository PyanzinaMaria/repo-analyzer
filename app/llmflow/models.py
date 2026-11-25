"""Data model of the LLM-flow module."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal

TargetKind = Literal["sink", "return", "prompt", "fn"]
Role = Literal["S", "I"]


@dataclass(frozen=True)
class Target:
    """What a taint rule looks for at its sink end.

    sink    a dangerous sink class from sinks.yaml (name = class)
    return  a `return` statement (finds wrappers that return LLM output)
    prompt  a prompt argument of any SDK call
    fn      an argument of a discovered wrapper function: role S (parameter reaches a sink) or
            I (parameter reaches a prompt); name = function simple name, param/pos = which argument
    """
    kind: TargetKind
    name: str
    param: str | None = None
    pos: int | None = None          # positional index, `self`/`cls` excluded
    role: Role | None = None

    @property
    def tid(self) -> str:
        if self.kind == "fn":
            return f"fn.{self.role}.{self.name}.{self.param}"
        return f"{self.kind}.{self.name}" if self.kind == "sink" else self.kind


@dataclass
class Match:
    """One Semgrep result, normalized."""
    rule_id: str
    family: str                     # callsite | o2s | i2p | par | gate | hygiene
    file: str
    line: int
    end_line: int
    col: int
    meta: dict
    fields: dict                    # values decoded from the rule message (@@K=V@@)
    func: str | None = None         # enclosing function id (app/context/index.py)
    message: str = ""


@dataclass
class ModelRef:
    name: str | None                # resolved model id or None
    how: str                        # literal | constant | env-default | env-file | dict-default | config | unknown
    detail: str = ""                # e.g. env var name, config file
    kb_id: str | None = None        # matched knowledge-base entry


@dataclass
class Tool:
    name: str
    func: str | None = None         # function id bound to the tool (dispatch dict / direct reference)
    func_name: str | None = None
    file: str | None = None
    line: int | None = None
    params: list[str] = field(default_factory=list)


@dataclass
class CallSite:
    id: str                         # "<file>:<line>"
    file: str
    line: int
    sdk: str
    call: str                       # catalog call id
    channel: str
    func: str | None                # enclosing function id
    func_name: str | None
    model: ModelRef
    tools: list[Tool] = field(default_factory=list)
    exposure: list[dict] = field(default_factory=list)   # untrusted sources that reach this prompt


@dataclass
class Hop:
    file: str
    line: int
    func: str | None                # function id
    func_name: str | None
    role: str                       # source | prompt | llm | wrapper | call | sink | tool
    label: str = ""
    code: str = ""
    approx: bool = False            # edge resolved by an ambiguous name


@dataclass
class GateHit:
    gate: str
    kind: str
    title: str
    factor: float
    file: str
    line: int
    func: str | None
    var: str = ""


@dataclass
class Flow:
    """An end-to-end path: [untrusted source →] prompt → LLM → … → dangerous sink."""
    id: str
    sink_class: str
    sink_title: str
    cwe: str
    channel: str
    hops: list[Hop]
    callsite: str | None            # CallSite.id of the LLM call
    model: str | None
    source_kind: str
    source_title: str
    S: float = 0.0
    E_base: float = 0.0
    E: float = 0.0
    R: float = 0.0
    priority: float = 0.0
    gates: list[GateHit] = field(default_factory=list)
    approx: bool = False
    rank: int = 0
    rank_by_S: int = 0
    # same source and sink reached through other LLM call sites (e.g. one `submit_prompt` per backend)
    alt_callsites: list[str] = field(default_factory=list)

    @property
    def gated(self) -> bool:
        return bool(self.gates)

    @property
    def sink(self) -> Hop:
        return self.hops[-1]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["gated"] = self.gated
        return d
