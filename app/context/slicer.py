"""Bounded context packs for a code location (spec §5.5)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import networkx as nx
from pydantic import BaseModel

from app.context.callgraph import callees, callers
from app.context.index import SnapshotIndex
from app.context.sinks import function_sinks

CHARS_PER_TOKEN = 3.5


def approx_tokens(text: str) -> int:
    return int(len(text) / CHARS_PER_TOKEN) + 1


class ContextPack(BaseModel):
    file: str
    line: int
    function: str | None
    text: str
    tokens: int
    sections: list[str]


@lru_cache(maxsize=256)
def _read_lines(path: str) -> tuple[str, ...]:
    try:
        return tuple(Path(path).read_text(encoding="utf-8", errors="replace").splitlines())
    except OSError:
        return ()


def numbered(root: Path, file: str, start: int, end: int, mark: set[int] | None = None) -> str:
    lines = _read_lines(str(root / file))
    start, end = max(1, start), min(len(lines), end)
    mark = mark or set()
    return "\n".join(f"{'>' if i in mark else ' '}{i:5d} | {lines[i - 1]}" for i in range(start, end + 1))


class Snapshot:
    """Index + call graph + entry points for one (item, side)."""

    def __init__(self, root: Path, idx: SnapshotIndex, graph: nx.DiGraph, entrypoints: dict[str, str]):
        self.root, self.idx, self.graph, self.entrypoints = root, idx, graph, entrypoints
        self.funcs = {fn.id: fn for fn in idx.all_functions()}


def make_pack(snap: Snapshot, file: str, line: int, end_line: int | None = None, budget_tokens: int = 6000,
              dataflow: list[dict] | None = None, extra_note: str | None = None) -> ContextPack:
    """Sections in priority order; lower-priority sections are dropped/trimmed to fit the budget."""
    budget_chars = int(budget_tokens * CHARS_PER_TOKEN)
    end_line = end_line or line
    fn = snap.idx.function_at(file, line)
    language = snap.idx.language
    fi = snap.idx.files.get(file)
    mark = set(range(line, end_line + 1))
    sections: list[tuple[str, str]] = []

    # 1. target code (always kept; trimmed to a window if huge)
    if fn is not None:
        body = numbered(snap.root, file, fn.start, fn.end, mark)
        if len(body) > budget_chars * 0.55:
            header = numbered(snap.root, file, fn.start, min(fn.end, fn.start + 4))
            window = numbered(snap.root, file, max(fn.start, line - 40), min(fn.end, end_line + 40), mark)
            body = header + "\n   ... (function truncated) ...\n" + window
        ep = snap.entrypoints.get(fn.id)
        title = f"## Target function `{fn.name}` in {file} (lines {fn.start}-{fn.end})"
        if ep:
            title += f" — entry point: {ep}"
        sections.append(("target", f"{title}\n```\n{body}\n```"))
    else:
        body = numbered(snap.root, file, line - 30, end_line + 30, mark)
        sections.append(("target", f"## Target code in {file} (module level)\n```\n{body}\n```"))

    # 2. SAST dataflow path
    if dataflow:
        steps = []
        for st in dataflow[:15]:
            snippet = (st.get("snippet") or "").strip().splitlines()
            steps.append(f"- {st.get('file')}:{st.get('line')}  {snippet[0][:160] if snippet else ''}")
        sections.append(("dataflow", "## Dataflow path reported by SAST (source → sink)\n" + "\n".join(steps)))

    # 3. imports of the file
    if fi and fi.imports:
        sections.append(("imports", "## Imports in " + file + "\n```\n" + "\n".join(fi.imports[:20]) + "\n```"))

    if fn is not None:
        # 4. callers up to depth 2
        parts = []
        for cid, call_line, dist in callers(snap.graph, fn.id, depth=2)[:8]:
            c = snap.funcs.get(cid)
            if not c:
                continue
            ep = snap.entrypoints.get(cid)
            head = numbered(snap.root, c.file, c.start, min(c.end, c.start + 2))
            near = numbered(snap.root, c.file, max(c.start, call_line - 2), min(c.end, call_line + 2), {call_line})
            parts.append(f"### caller (depth {dist}) `{c.name}` in {c.file}{' — entry point: ' + ep if ep else ''}"
                         f"\n```\n{head}\n   ...\n{near}\n```")
        if parts:
            sections.append(("callers", "## Callers\n" + "\n".join(parts)))
        elif not snap.entrypoints.get(fn.id):
            sections.append(("callers", "## Callers\n(no callers found by name-based resolution)"))

        # 5. callees that reach a sink
        parts = []
        for cid, dist in callees(snap.graph, fn.id, depth=2):
            c = snap.funcs.get(cid)
            if not c:
                continue
            hits = function_sinks(c, language)
            if not hits:
                continue
            lines = {h.line for h in hits}
            snippet = "\n   ...\n".join(numbered(snap.root, c.file, max(c.start, ln - 2), min(c.end, ln + 2), {ln})
                                        for ln in sorted(lines)[:3])
            parts.append(f"### callee (depth {dist}) `{c.name}` in {c.file} — sinks: "
                         f"{', '.join(sorted({h.callee + ' (' + h.cwe + ')' for h in hits}))}\n```\n"
                         f"{numbered(snap.root, c.file, c.start, min(c.end, c.start + 2))}\n   ...\n{snippet}\n```")
            if len(parts) >= 5:
                break
        if parts:
            sections.append(("callees", "## Callees that reach dangerous sinks\n" + "\n".join(parts)))

    if extra_note:
        sections.append(("note", extra_note))

    # fit budget: drop from the end (lowest priority), then hard-truncate the target
    def total(secs):
        return sum(len(s) + 2 for _, s in secs)

    while len(sections) > 1 and total(sections) > budget_chars:
        sections.pop()
    if total(sections) > budget_chars:
        name, text = sections[0]
        sections[0] = (name, text[: budget_chars - 40] + "\n... (truncated)\n```")
    text = "\n\n".join(s for _, s in sections)
    return ContextPack(file=file, line=line, function=fn.name if fn else None, text=text,
                       tokens=approx_tokens(text), sections=[n for n, _ in sections])
