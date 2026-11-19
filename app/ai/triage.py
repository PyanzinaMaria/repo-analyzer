"""Mode T — triage of merged SAST findings: is each warning a real, exploitable vulnerability?

Findings are judged in batches (default up to 5 per call, grouped by file) so that free-tier request caps go
further. Each finding still gets its own verdict, CWE and explanation. Used by the analyzer service
(app/ai/service.py) and by the benchmark runner (bench/llm.py).
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from app.ai.common import assert_no_leak, framework_hints, redact_ids
from app.ai.llm import LLMClient
from app.ai.prompting import render
from app.ai.schemas import TriageBatchResult, TriageResult
from app.context.slicer import Snapshot, make_pack
from app.core.runlog import RunSummary
from app.sast.normalize import MergedFinding


def group_findings(findings: list[MergedFinding], per_prompt: int) -> list[list[MergedFinding]]:
    """Chunks of `per_prompt` findings sorted by (file, line): neighbours share context, and the number
    of calls per snapshot is ceil(n / per_prompt)."""
    ordered = sorted(findings, key=lambda f: (f.file, f.start_line))
    return [ordered[i:i + per_prompt] for i in range(0, len(ordered), per_prompt)]


def triage_findings(client: LLMClient, model_id: str, snap: Snapshot, language: str,
                    findings: list[MergedFinding], budget_tokens: int = 6000, per_prompt: int = 5,
                    summary: RunSummary | None = None, tag: str = "triage") -> list[dict]:
    """One row per finding: {finding_id, file, lines, cwe, tools, result (TriageResult dict) | None, score,
    pending, error, cached, cost, batch_size}."""
    summary = summary or RunSummary(tag)
    hints = framework_hints(snap)

    def one(group: list[MergedFinding]) -> list[dict]:
        # one context pack per distinct enclosing function (findings in the same function share it)
        def fn_key(f: MergedFinding) -> str:
            fn = snap.idx.function_at(f.file, f.start_line)
            return fn.id if fn else f"{f.file}:{f.start_line}"

        distinct: dict[str, MergedFinding] = {}
        for f in group:
            distinct.setdefault(fn_key(f), f)
        per_pack = max(1500, int(budget_tokens * 1.5) // len(distinct))
        packs = []
        for f in distinct.values():
            flow = [s.model_dump() for s in f.dataflow] if f.dataflow else None
            packs.append(make_pack(snap, f.file, f.start_line, f.end_line, budget_tokens=per_pack, dataflow=flow))
        system, user = render("triage", language=language, findings=group, framework_hints=hints,
                              contexts=[redact_ids(p.text) for p in packs])
        assert_no_leak(system, user)
        res = client.complete_json(model_id, system, user, TriageBatchResult,
                                   params={"max_tokens": 1200 + 600 * len(group)}, tag=tag)
        by_num = {r.finding: r for r in res.obj.results} if res.obj else {}
        rows = []
        for i, f in enumerate(group, start=1):
            r = by_num.get(i)
            result = TriageResult.model_validate(r.model_dump(exclude={"finding"})) if r else None
            rows.append({"finding_id": f.id, "file": f.file, "start_line": f.start_line, "end_line": f.end_line,
                         "cwe": f.cwe, "tools": f.tools, "context_tokens": sum(p.tokens for p in packs),
                         "result": result.model_dump() if result else None,
                         "score": result.score if result else None, "pending": res.pending,
                         "error": res.error or (None if result or res.pending else "finding missing in answer"),
                         "cached": res.cached, "cost": res.cost if i == 1 else 0.0, "batch_size": len(group)})
        return rows

    groups = group_findings(findings, per_prompt)
    workers = client.cfg.backends[client.spec(model_id).backend].max_concurrency
    rows: list[dict] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        for batch in ex.map(one, groups):
            for row in batch:
                rows.append(row)
                summary.cost_usd += row["cost"]
                summary.inc("pending" if row["pending"] else ("ok" if row["result"] else "invalid/missing"))
    summary.inc("calls", len(groups))
    return rows
