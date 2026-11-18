"""Normalized findings (spec §4.2) and merging of near-duplicates across tools (spec §4.3)."""

from __future__ import annotations

import hashlib
from typing import Literal

from pydantic import BaseModel

from app.sast.cwe_map import cwe_overlap
from app.sast.sarif import FlowStep, RawFinding

Side = Literal["vuln", "fixed", "adhoc"]

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, None: 0}


class Finding(BaseModel):
    id: str
    item_id: str
    side: Side
    tool: str
    rule_id: str
    cwe: list[str]
    severity: str | None
    file: str
    start_line: int
    end_line: int
    message: str
    dataflow: list[FlowStep] | None = None


class MergedFinding(BaseModel):
    id: str
    item_id: str
    side: Side
    file: str
    start_line: int
    end_line: int
    cwe: list[str]
    tools: list[str]
    rule_ids: list[str]
    severity: str | None
    messages: list[str]
    dataflow: list[FlowStep] | None = None
    members: list[str]

    @property
    def n_tools(self) -> int:
        return len(self.tools)


def finding_id(tool: str, rule_id: str, file: str, line: int) -> str:
    return hashlib.sha256(f"{tool}|{rule_id}|{file}|{line}".encode()).hexdigest()[:16]


def normalize(raw: list[RawFinding], item_id: str, side: Side) -> list[Finding]:
    seen: dict[str, Finding] = {}
    for r in raw:
        fid = finding_id(r.tool, r.rule_id, r.file, r.start_line)
        if fid in seen:  # same tool/rule/line reported twice (e.g. multiple paths): keep first
            continue
        seen[fid] = Finding(id=fid, item_id=item_id, side=side, **r.model_dump())
    return sorted(seen.values(), key=lambda f: (f.file, f.start_line, f.tool, f.rule_id))


def _compatible(a: Finding, cluster: list[Finding], tol: int) -> bool:
    for b in cluster:
        if abs(a.start_line - b.start_line) > tol:
            continue
        if cwe_overlap(a.cwe, b.cwe):
            return True
        if not a.cwe and not b.cwe and a.start_line == b.start_line:
            return True
    return False


def merge(findings: list[Finding], tol: int = 3) -> list[MergedFinding]:
    """Greedy clustering: same file, |line diff| <= tol, overlapping CWE (with CWE families)."""
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)
    merged: list[MergedFinding] = []
    for file, fs in sorted(by_file.items()):
        clusters: list[list[Finding]] = []
        for f in sorted(fs, key=lambda x: x.start_line):
            for c in clusters:
                if _compatible(f, c, tol):
                    c.append(f)
                    break
            else:
                clusters.append([f])
        for c in clusters:
            tools = sorted({f.tool for f in c})
            cwes: list[str] = []
            for f in c:
                cwes += [x for x in f.cwe if x not in cwes]
            sev = max((f.severity for f in c), key=lambda s: SEVERITY_RANK.get(s, 0))
            flow = next((f.dataflow for f in c if f.tool == "codeql" and f.dataflow), None) or next(
                (f.dataflow for f in c if f.dataflow), None)
            members = [f.id for f in c]
            mid = hashlib.sha256("|".join(sorted(members)).encode()).hexdigest()[:16]
            merged.append(MergedFinding(
                id=mid, item_id=c[0].item_id, side=c[0].side, file=file,
                start_line=min(f.start_line for f in c), end_line=max(f.end_line for f in c),
                cwe=cwes, tools=tools, rule_ids=sorted({f"{f.tool}:{f.rule_id}" for f in c}),
                severity=sev, messages=list(dict.fromkeys(f.message for f in c))[:5],
                dataflow=flow, members=members,
            ))
    return merged


def rank_sast(merged: list[MergedFinding]) -> list[MergedFinding]:
    """Configuration `S` ranking: tool agreement, then severity, then dataflow presence."""
    return sorted(merged, key=lambda m: (-m.n_tools, -SEVERITY_RANK.get(m.severity, 0),
                                         m.dataflow is None, m.file, m.start_line))
