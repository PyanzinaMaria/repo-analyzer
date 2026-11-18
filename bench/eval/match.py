"""Matching reported locations to ground truth (spec §7.1)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

GT_KINDS = ("fix_hunk", "sink", "vuln_function")

# function_at(file, line) -> (start, end) of the innermost enclosing function, or None
FunctionResolver = Callable[[str, int], tuple[int, int] | None]


@dataclass(frozen=True)
class GTSpan:
    file: str
    start: int
    end: int
    fn_start: int | None
    fn_end: int | None
    kind: str

    @property
    def fn_length(self) -> int | None:
        return None if self.fn_start is None else self.fn_end - self.fn_start + 1


def gt_spans(item: dict, side: str) -> list[GTSpan]:
    out = []
    for g in item["gt_locations"]:
        if g["kind"] not in GT_KINDS:
            continue
        if side == "vuln":
            out.append(GTSpan(g["file"], g["start_line"], g["end_line"], g.get("function_start"),
                              g.get("function_end"), g["kind"]))
        elif g.get("fixed_file") and g.get("fixed_start_line"):
            out.append(GTSpan(g["fixed_file"], g["fixed_start_line"], g["fixed_end_line"],
                              g.get("fixed_function_start"), g.get("fixed_function_end"), g["kind"]))
    return out


def line_hit(entry: dict, gt: GTSpan, tol: int) -> bool:
    if entry["file"] != gt.file:
        return False
    s, e = entry["start_line"] - tol, entry["end_line"] + tol
    return s <= gt.end and gt.start <= e


def function_hit(entry: dict, gt: GTSpan, resolve: FunctionResolver | None, tol: int) -> bool:
    """Same file and same enclosing function. Module-level GT (no function) falls back to a line hit.
    `vuln_function` GT spans are whole functions, so any line inside them counts."""
    if entry["file"] != gt.file:
        return False
    if gt.kind == "vuln_function":
        return gt.start <= entry["start_line"] <= gt.end or line_hit(entry, gt, 0)
    if gt.fn_start is None:
        return line_hit(entry, gt, tol)
    if resolve is not None:
        span = resolve(entry["file"], entry["start_line"])
        return span == (gt.fn_start, gt.fn_end)
    return gt.fn_start <= entry["start_line"] <= gt.fn_end


@dataclass
class HitInfo:
    func_rank: int | None      # 1-based rank of the first function hit
    line_rank: int | None
    func_hit_long_fn: bool     # first function hit is in a function longer than the guard
    cwe_agree: bool | None     # CWE of first function hit overlaps the item CWE


def first_hits(ranked: list[dict], gts: list[GTSpan], tol: int, resolve: FunctionResolver | None = None,
               item_cwes: list[str] | None = None, max_fn_lines: int | None = None) -> HitInfo:
    from app.sast.cwe_map import cwe_overlap

    f_rank = l_rank = None
    long_fn = False
    cwe_agree = None
    for i, e in enumerate(ranked, start=1):
        if l_rank is None and any(line_hit(e, g, tol) for g in gts):
            l_rank = i
        if f_rank is None:
            matched = [g for g in gts if function_hit(e, g, resolve, tol)]
            if matched:
                f_rank = i
                long_fn = bool(max_fn_lines and all((g.fn_length or 0) > max_fn_lines for g in matched))
                cwe_agree = cwe_overlap(e.get("cwe") or [], item_cwes or []) if item_cwes else None
        if f_rank is not None and l_rank is not None:
            break
    return HitInfo(f_rank, l_rank, long_fn, cwe_agree)


def flagged_within(ranked: list[dict], gts: list[GTSpan], k: int | None, tol: int,
                   resolve: FunctionResolver | None = None, level: str = "function") -> bool:
    lst = ranked if k is None else ranked[:k]
    if level == "line":
        return any(line_hit(e, g, tol) for e in lst for g in gts)
    return any(function_hit(e, g, resolve, tol) for e in lst for g in gts)
