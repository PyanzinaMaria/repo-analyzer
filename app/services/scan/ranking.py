"""Final ranking of a scan and the audit document built from it.

Same configurations as the benchmark (app/ai/rank.py): S (SAST by tool agreement and severity), S+T (re-ranked
by LLM triage, false positives removed), S+D (SAST fused with LLM discovery), S+T+D (triaged SAST fused with
hybrid discovery). The best configuration available for this scan is used.
"""

from __future__ import annotations

import hashlib
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.ai.rank import rank_L, rank_S, rank_ST, rrf
from app.core import io
from app.models.finding import Finding, Severity
from app.sast.engine import CWE_TITLES_RU, REMEDIATION_RU, LanguageRun
from app.services.report.audit import AuditData

SNIPPET_TOP = 25          # findings that get an embedded code snippet (self-contained HTML reports)
SNIPPET_CONTEXT = 3


@dataclass
class ScanRanking:
    config: str                                   # S | S+T | S+D | S+T+D
    entries: list[dict] = field(default_factory=list)
    removed: list[dict] = field(default_factory=list)    # triage rows judged false_positive
    new_findings: list[Finding] = field(default_factory=list)

    def to_json(self) -> dict:
        return {"config": self.config, "entries": self.entries, "removed": self.removed}

    @classmethod
    def from_json(cls, data: dict) -> "ScanRanking":
        return cls(config=data.get("config", "S"), entries=data.get("entries", []), removed=data.get("removed", []))


def _config(has_triage: bool, has_discovery: bool) -> str:
    return {(True, True): "S+T+D", (True, False): "S+T", (False, True): "S+D"}.get((has_triage, has_discovery), "S")


def rank_language(run: LanguageRun, llm: dict[str, Any] | None) -> tuple[str, list[dict], list[dict]]:
    llm = llm or {}
    S = rank_S(run.merged)
    tri, disc = llm.get("triage"), llm.get("discovery")
    ST = rank_ST(S, tri) if tri else None
    L = rank_L(disc) if disc is not None else None
    cfg = _config(ST is not None, L is not None)
    final = {"S+T+D": lambda: rrf([ST, L]), "S+T": lambda: ST, "S+D": lambda: rrf([S, L]), "S": lambda: S}[cfg]()
    removed = [r for r in (tri or []) if r.get("result") and r.get("score") == 0]
    for e in final:
        e["language"] = run.language
    return cfg, final, removed


def _severity_for_llm(cwe: str | None, confidence: float) -> Severity:
    from app.ai.discovery import severity_weight

    w = severity_weight(cwe or "")
    if w >= 0.9 and confidence >= 0.8:
        return Severity.critical if w >= 1.0 else Severity.high
    if w >= 0.8:
        return Severity.high
    return Severity.medium if confidence >= 0.5 else Severity.low


def _llm_finding(e: dict) -> Finding:
    ll = e.get("llm") or {}
    cwe = (e.get("cwe") or [None])[0]
    key = hashlib.sha256(f"{e['file']}|{e['start_line']}|{cwe}".encode()).hexdigest()[:12]
    title = ll.get("title") or e.get("title") or CWE_TITLES_RU.get(cwe or "", cwe or "Находка ИИ")
    return Finding(
        id=f"ai-{key}", title=title, description=(ll.get("explanation") or "").strip(),
        severity=_severity_for_llm(cwe, float(ll.get("confidence") or 0.0)), cwe=cwe, file=e["file"],
        line=e["start_line"], rule_id=None, source="ai-discovery",
        language=e.get("language", "unknown").replace("typescript", "javascript"),
        remediation=REMEDIATION_RU.get(cwe or "", "Проверьте найденный путь данных и устраните уязвимость."),
        extra={"end_line": e["end_line"], "llm": ll},
    )


def _snippet(root: Path, file: str, start: int, end: int) -> dict | None:
    path = root / file
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    hl_end = end if end - start <= 6 else start
    s = max(1, start - SNIPPET_CONTEXT)
    t = min(len(lines), hl_end + SNIPPET_CONTEXT)
    return {"start": s, "lines": lines[s - 1:t], "highlight": [start, hl_end]}


def rank_scan(root: Path, findings: list[Finding], runs: list[LanguageRun],
              llm_results: dict[str, dict[str, Any]] | None = None) -> ScanRanking:
    """Rank every language, merge them by position, annotate `findings` in place (extra.rank, verdicts,
    explanations, snippets) and return LLM-only findings to append."""
    llm_results = llm_results or {}
    per_lang = [rank_language(run, llm_results.get(run.language)) for run in runs]
    configs = {cfg for cfg, _, _ in per_lang} or {"S"}
    config = max(configs, key=["S", "S+D", "S+T", "S+T+D"].index)
    # interleave languages by position (scores of different configurations are not comparable)
    lists = [lst for _, lst, _ in per_lang]
    entries: list[dict] = []
    for i in range(max((len(x) for x in lists), default=0)):
        entries += [lst[i] for lst in lists if i < len(lst)]
    ranking = ScanRanking(config=config, entries=entries,
                          removed=[r for _, _, rem in per_lang for r in rem])

    by_cluster = {f.extra.get("cluster_id"): f for f in findings if f.extra.get("cluster_id")}
    for r in ranking.removed:
        f = by_cluster.get(r["finding_id"])
        if f is not None:
            f.extra.update(dismissed=True, verdict="false_positive", triage=r["result"])
    for rank, e in enumerate(entries, start=1):
        f = by_cluster.get(e.get("id")) if e.get("id") else None
        if f is None:
            f = _llm_finding(e)
            ranking.new_findings.append(f)
        f.extra.update(rank=rank, rank_score=round(float(e.get("score") or 0), 6), origin=e.get("origin"))
        for key in ("verdict", "triage", "llm"):
            if e.get(key) is not None:
                f.extra[key] = e[key]
        if rank <= SNIPPET_TOP and f.file:
            snip = _snippet(root, f.file, e["start_line"], e["end_line"])
            if snip:
                f.extra["snippet"] = snip
    return ranking


def ordered(findings: list[Finding]) -> list[Finding]:
    """Ranked findings first (by rank), then the rest (pip-audit, file review); dismissed ones last."""
    return sorted(findings, key=lambda f: (bool(f.extra.get("dismissed")), f.extra.get("rank") is None,
                                           f.extra.get("rank") or 0))


def git_commit(root: Path) -> str | None:
    if not (root / ".git").exists():
        return None
    try:
        out = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True,
                             timeout=30)
        return out.stdout.strip() or None if out.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def audit_data(root: Path, name: str, runs: list[LanguageRun], ranking: ScanRanking, model: str | None,
               repo_url: str | None = None) -> AuditData:
    """AuditData for the terminal / Markdown audit renderers (app/services/report/audit.py)."""
    item = {"name": name, "language": ", ".join(r.language for r in runs) or "-", "loc": sum(r.loc for r in runs)}
    commit = git_commit(root)
    if repo_url and repo_url.startswith("https://github.com/"):
        item["repo_url"] = repo_url.rstrip("/").removesuffix(".git")
    data = AuditData(item=item, side="workspace", model=model, config=ranking.config, ranked=ranking.entries,
                     root=root, commit=commit, removed=ranking.removed)
    ctx: Counter = Counter()
    for run in runs:
        for k, v in (run.context or {}).items():
            if isinstance(v, int):
                ctx[k] += v
        cdir = run.context_dir
        if (cdir / "entrypoints.json").exists():
            data.entry_kinds.update(io.read_json(cdir / "entrypoints.json").values())
        if (cdir / "sinks.json").exists():
            data.sink_cwes.update(s["cwe"] for s in io.read_json(cdir / "sinks.json"))
        for tool, st in run.tools.items():
            cur = data.sast.setdefault(tool, {"ok": False, "seconds": 0, "findings": 0})
            cur["ok"] = cur["ok"] or st.get("ok", False)
            cur["seconds"] += st.get("seconds", 0)
            cur["findings"] += st.get("findings", 0)
        if data.idx is None and (cdir / "index.json").exists():
            from app.context.index import load_index

            data.idx = load_index(cdir / "index.json")
    data.context = dict(ctx)
    return data


def runs_from_meta(language_meta: dict) -> list[LanguageRun]:
    """Static-stage results recorded in ScanResult.meta['languages'][*]['secaudit']."""
    runs = []
    for info in language_meta.values():
        m = (info or {}).get("secaudit")
        if not m:
            continue
        run = LanguageRun(language=m["language"], work_dir=Path(m["work_dir"]))
        run.tools, run.context, run.loc, run.errors = m["tools"], m["context"], m["loc"], m["errors"]
        runs.append(run)
    return runs


def audit_from_scan(result, root: Path, work_dir: Path, repo_url: str | None = None) -> AuditData:
    """Rebuild the audit document of a finished scan (used by `python -m app scan` for terminal/SVG output)."""
    ranking = ScanRanking.from_json(io.read_json(work_dir / "ranking.json"))
    llm = (result.meta or {}).get("llm") or {}
    runs = runs_from_meta((result.meta or {}).get("languages") or {})
    return audit_data(root, result.project_name, runs, ranking, llm.get("model") if llm.get("enabled") else None,
                      repo_url)
