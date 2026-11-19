"""Ranked finding lists for each configuration (spec §6.5).

Entry: {"file", "start_line", "end_line", "cwe": [..], "score", "origin"}.
  S          SAST only, rank by tool agreement then severity
  S-<tool>   one SAST tool
  L          LLM discovery only
  S+T        SAST re-ranked by triage score; findings judged false_positive are dropped,
             untriaged findings (beyond the triage cap) keep their S order after the triaged ones
  S+D        reciprocal-rank fusion of S and L
  S+T+D      reciprocal-rank fusion of S+T and D+ (hybrid discovery; falls back to L)
"""

from __future__ import annotations

from app.sast.cwe_map import cwe_overlap
from app.sast.normalize import MergedFinding, rank_sast

SAST_TOOLS = ["semgrep", "bandit", "eslint", "codeql"]
MODEL_CONFIGS = ["L", "S+T", "S+D", "S+T+D"]


def _entry(file, start, end, cwe, score, origin, **extra) -> dict:
    return {"file": file, "start_line": start, "end_line": end, "cwe": list(cwe), "score": score,
            "origin": origin, **extra}


def rank_S(merged: list[MergedFinding], tool: str | None = None) -> list[dict]:
    ms = [m for m in merged if tool is None or tool in m.tools]
    n = len(ms)
    return [_entry(m.file, m.start_line, m.end_line, m.cwe, round(1 - i / max(n, 1), 4), "sast", id=m.id,
                   tools=m.tools, rule_ids=m.rule_ids, severity=m.severity,
                   message=(m.messages[0] if m.messages else "")) for i, m in enumerate(rank_sast(ms))]


def rank_ST(S: list[dict], triage_rows: list[dict]) -> list[dict]:
    by_id = {r["finding_id"]: r for r in triage_rows}
    judged, rest = [], []
    for e in S:
        r = by_id.get(e["id"])
        if r is None or r.get("result") is None:
            rest.append(e)
            continue
        if r["score"] <= 0:
            continue  # false positive: removed
        judged.append({**e, "score": r["score"], "origin": "sast+triage",
                       "verdict": r["result"]["verdict"], "triage": r["result"]})
    judged.sort(key=lambda e: -e["score"])
    return judged + rest


def rank_L(rows: list[dict]) -> list[dict]:
    keep = ("title", "function", "confidence", "source_to_sink", "explanation", "exploit_sketch", "support")
    return [_entry(r["file"], r["start_line"], r["end_line"], [r["cwe"]], r.get("score", r["confidence"]), "llm",
                   llm={k: r.get(k) for k in keep}, title=r.get("title")) for r in rows]


def same_location(a: dict, b: dict, tol: int = 3) -> bool:
    if a["file"] != b["file"] or abs(a["start_line"] - b["start_line"]) > tol:
        return False
    return not a["cwe"] or not b["cwe"] or cwe_overlap(a["cwe"], b["cwe"]) or a["start_line"] == b["start_line"]


def rrf(lists: list[list[dict]], k: int = 60) -> list[dict]:
    """Reciprocal-rank fusion with location dedup."""
    fused: list[dict] = []
    for lst in lists:
        for rank, e in enumerate(lst, start=1):
            s = 1.0 / (k + rank)
            hit = next((f for f in fused if same_location(f, e)), None)
            if hit:
                hit["score"] += s
                hit["origin"] = "+".join(sorted(set(hit["origin"].split("+")) | set(e["origin"].split("+"))))
                for key in ("triage", "verdict", "llm", "title", "tools", "rule_ids", "message", "severity", "id"):
                    if e.get(key) is not None and hit.get(key) is None:
                        hit[key] = e[key]
            else:
                fused.append({**e, "score": s})
    return sorted(fused, key=lambda e: -e["score"])
