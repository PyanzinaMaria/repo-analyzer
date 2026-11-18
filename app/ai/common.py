"""Shared helpers for LLM triage/discovery: framework hints, guard against ground-truth leakage."""

from __future__ import annotations

import re
from app.context.slicer import Snapshot

FRAMEWORK_PATTERNS = {
    "flask": r"\bflask\b", "django": r"\bdjango\b", "fastapi": r"\bfastapi\b", "tornado": r"\btornado\b",
    "aiohttp": r"\baiohttp\b", "express": r"\bexpress\b", "koa": r"\bkoa\b", "fastify": r"\bfastify\b",
    "nestjs": r"@nestjs", "next": r"\bnext/", "electron": r"\belectron\b",
}


def framework_hints(snap: Snapshot, file: str | None = None) -> str:
    texts = []
    files = [snap.idx.files[file]] if file and file in snap.idx.files else list(snap.idx.files.values())[:200]
    for fi in files:
        texts += fi.imports
    blob = "\n".join(texts).lower()
    found = [name for name, rx in FRAMEWORK_PATTERNS.items() if re.search(rx, blob)]
    return ", ".join(found)


_LEAK_RE = re.compile(r"\b(CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})\b", re.I)


def assert_no_leak(*texts: str) -> None:
    """Rule 5: no CVE/GHSA ids in prompts. Code comments mentioning a CVE are redacted upstream."""
    for t in texts:
        m = _LEAK_RE.search(t)
        if m:
            raise AssertionError(f"ground-truth identifier in prompt: {m.group(0)}")


def redact_ids(text: str) -> str:
    """Redact CVE/GHSA ids that appear in source comments (e.g. in the fixed snapshot)."""
    return _LEAK_RE.sub("<ID-REDACTED>", text)
