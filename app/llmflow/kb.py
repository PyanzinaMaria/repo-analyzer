"""Model knowledge base (WP7): model name → KB entry → R per channel."""

from __future__ import annotations

import re

from app.llmflow.catalog import KbConfig, KbModel


def match_model(kb: KbConfig, name: str | None) -> KbModel | None:
    if not name:
        return None
    n = name.strip().lower()
    # `llama3.1:8b` (ollama tags), `models/gpt-4o` → match the family part
    n = n.split(":")[0]
    if "/" in n and not any(re.search(a, n) for m in kb.models for a in m.aliases):
        n = n.rsplit("/", 1)[-1]
    best = None
    for m in kb.models:
        for a in m.aliases:
            hit = re.search(a, n)
            # prefer the most specific alias (gpt-4o-mini over gpt-4o)
            if hit and (best is None or len(hit.group(0)) > best[1]):
                best = (m, len(hit.group(0)))
    return best[0] if best else None


def r_value(kb: KbConfig, model: str | None, channel: str) -> tuple[float, str | None]:
    """(R, kb id). Unknown models get the default R."""
    m = match_model(kb, model)
    if m is None:
        r = kb.defaults.R
    else:
        r = m.R.channels.get(channel, m.R.default)
    return max(kb.defaults.min, min(kb.defaults.max, r)), (m.id if m else None)
