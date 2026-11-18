"""Sink catalog matching (spec §5.4)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from app.core.yaml_configs import CONFIG_DIR
from app.context.index import CallSite, FuncInfo


@dataclass(frozen=True)
class SinkRule:
    callee: re.Pattern
    cwe: str
    args: re.Pattern | None = None
    only: re.Pattern | None = None    # extra constraint on the full callee text


@dataclass(frozen=True)
class SinkHit:
    file: str
    line: int
    callee: str
    cwe: str
    function_id: str | None


@lru_cache(maxsize=None)
def load_catalog(path: str = str(CONFIG_DIR / "sinks.yaml")) -> dict[str, list[SinkRule]]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    out: dict[str, list[SinkRule]] = {}
    for lang, rules in data.items():
        out[lang] = [SinkRule(callee=re.compile(r["callee"]), cwe=r["cwe"],
                              args=re.compile(r["args"]) if r.get("args") else None,
                              only=re.compile(r["only"]) if r.get("only") else None) for r in rules]
    out["typescript"] = out.get("javascript", [])
    return out


def match_call(call: CallSite, rules: list[SinkRule]) -> str | None:
    for r in rules:
        if not r.callee.search(call.callee):
            continue
        if r.only is not None and not r.only.search(call.callee):
            continue
        if r.args is not None and not r.args.search(call.args):
            continue
        return r.cwe
    return None


def function_sinks(fn: FuncInfo, language: str) -> list[SinkHit]:
    rules = load_catalog()[language]
    hits = []
    for c in fn.calls:
        cwe = match_call(c, rules)
        if cwe:
            hits.append(SinkHit(fn.file, c.line, c.callee, cwe, fn.id))
    return hits


def catalog_text(language: str) -> str:
    """Compact human-readable sink list for prompts."""
    rules = load_catalog()[language]
    by_cwe: dict[str, list[str]] = {}
    for r in rules:
        by_cwe.setdefault(r.cwe, []).append(r.callee.pattern.replace("\\.", ".").replace("(^|.)", "")
                                            .replace("^", "").replace("$", ""))
    return "\n".join(f"- {cwe}: {', '.join(p)}" for cwe, p in sorted(by_cwe.items()))
