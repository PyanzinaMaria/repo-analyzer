from __future__ import annotations

"""Payload delivery strategies (the promptfoo idea: plugin x strategy).

A strategy transforms a raw payload so the same vulnerability class is tested
with different encodings / obfuscations. Detectors stay plugin-specific; the
HTTP verifier applies strategies uniformly.
"""

from typing import Callable
from urllib.parse import quote

Strategy = Callable[[str], str]


def raw(payload: str) -> str:
    return payload


def urlencode(payload: str) -> str:
    return quote(payload, safe="")


def double_urlencode(payload: str) -> str:
    return quote(quote(payload, safe=""), safe="")


def case_swap(payload: str) -> str:
    """Alternate case for case-insensitive filters (keyword obfuscation)."""
    return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload))


def sql_comment(payload: str) -> str:
    """Whitespace -> inline SQL comment (classic filter bypass for SQLi)."""
    return payload.replace(" ", "/**/")


def space_tab(payload: str) -> str:
    """Whitespace -> tabs (command injection / shell filters)."""
    return payload.replace(" ", "\t")


STRATEGIES: dict[str, Strategy] = {
    "raw": raw,
    "urlencode": urlencode,
    "double_urlencode": double_urlencode,
    "case": case_swap,
    "sql_comment": sql_comment,
    "space_tab": space_tab,
}


def apply_strategies(payload: str, names: tuple[str, ...] | list[str]) -> list[tuple[str, str]]:
    """Return [(strategy_name, transformed_payload)] with duplicates removed."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for name in names:
        fn = STRATEGIES.get(name)
        if fn is None:
            continue
        value = fn(payload)
        if value in seen:
            continue
        seen.add(value)
        out.append((name, value))
    return out


def strategy_names(strategies: tuple[str, ...], plugin_default: tuple[str, ...]) -> dict[str, tuple[str, ...]]:
    """Strategy set per plugin: global list, plus plugin-specific extras."""
    return {name: strategies for name in plugin_default}
