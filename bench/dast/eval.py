"""DAST evaluation: join per-tool findings with ground truth -> results/dast_metrics.json
and results/dast_report.md. OWASP corpora are scored per test case (endpoint-level TP/FP/FN,
precision/recall, TP-rate/FP-rate like the upstream benchmark); RealVuln per item by CWE
overlap. Non-test-URL findings are counted as FP and also reported separately.
"""

from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from pathlib import Path

from app.core import io
from bench.config import Paths
from bench.dast.config import DastBenchConfig, load_dast_config
from bench.dast.match import by_category, by_cwe, classify_item, classify_owasp, owasp_tests
from bench.external import _group_id, load_config as load_external_config


def _j(v: float) -> float | None:
    """JSON-safe float: NaN -> None."""
    return None if v is None or v != v else round(float(v), 4)


def prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else math.nan
    r = tp / (tp + fn) if tp + fn else math.nan
    f1 = 2 * p * r / (p + r) if p + r else math.nan
    return {"precision": _j(p), "recall": _j(r), "f1": _j(f1), "tp": tp, "fp": fp, "fn": fn}


def _load_findings(paths: Paths, target_ids: list[str]) -> dict[str, dict[str, list]]:
    """target_id -> tool -> [DastFinding] from dast/<tid>/<tool>.findings.jsonl."""
    from bench.dast.config import DastFinding as Model

    per_target: dict[str, dict[str, list]] = {}
    for tid in target_ids:
        tools: dict[str, list] = {}
        for f in sorted((paths.dast / tid).glob("*.findings.jsonl")):
            tools[f.name.removesuffix(".findings.jsonl")] = [
                Model(**row) for row in io.read_jsonl(f)]
        per_target[tid] = tools
    return per_target


def _seconds(paths: Paths, target_ids: list[str]) -> dict[str, float]:
    out: dict[str, float] = {}
    for tid in target_ids:
        for f in (paths.dast / tid).glob("*.status.json"):
            try:
                st = io.read_json(f)
            except (ValueError, OSError):
                continue
            if st.get("ok") and st.get("seconds"):
                out[f.name.removesuffix(".status.json")] = out.get(
                    f.name.removesuffix(".status.json"), 0.0) + float(st["seconds"])
    return out


def _coverage(paths: Paths, target_ids: list[str], tools: list[str]) -> dict:
    cov: dict[str, dict[str, int]] = {}
    for tid in target_ids:
        for f in (paths.dast / tid).glob("*.status.json"):
            try:
                st = io.read_json(f)
            except (ValueError, OSError):
                continue
            tool = f.name.removesuffix(".status.json")
            key = "ok" if st.get("ok") else ("skipped" if st.get("skipped") else "failed")
            cov.setdefault(tool, {})[key] = cov.get(tool, {}).get(key, 0) + 1
    for tool in tools:
        cov.setdefault(tool, {})
    return cov


def evaluate(kind: str, paths: Paths | None = None, cfg: DastBenchConfig | None = None) -> Path:
    paths = paths or Paths()
    cfg = cfg or load_dast_config()

    state = _read_state(paths)
    targets = {tid: rec for tid, rec in state.items()
               if rec.get("kind") == kind and rec.get("status") in ("up", "boot_failed")}
    live = sorted(tid for tid, rec in targets.items() if rec.get("status") == "up")
    per_target = _load_findings(paths, live)
    seconds = _seconds(paths, live)
    coverage = _coverage(paths, live, list(cfg.tools))

    tools = sorted({t for tools_map in per_target.values() for t in tools_map})
    metrics: dict[str, dict] = {}
    if kind.startswith("owasp"):
        tests = _owasp_gt(paths, kind)
        for tool in tools:
            findings = [f for tools_map in per_target.values() for f in tools_map.get(tool, [])]
            base = classify_owasp(findings, tests)
            row = prf(base["tp"], base["fp"], base["fn"])
            row.update(n_tests=base["n_tests"], n_true=base["n_true"], n_false=base["n_false"],
                       tp_rate=_j(base["tp"] / base["n_true"]) if base["n_true"] else None,
                       fp_rate=_j(base["fp"] / base["n_false"]) if base["n_false"] else None,
                       non_test_findings=base["non_test_findings"],
                       cwe_labelled=base["cwe_labelled"],
                       cwe_agreement=_j(base["cwe_agree_hits"] / base["cwe_labelled"])
                       if base["cwe_labelled"] else None,
                       seconds=_j(seconds.get(tool)), by_category=by_category(findings, tests),
                       by_cwe=by_cwe(findings, tests))
            metrics[tool] = row
        mode = "owasp"
    else:
        items = _items_cwes(paths, live)
        for tool in tools:
            agg = {"n_items": 0, "items_hit": 0, "tp": 0, "fp": 0, "fn": 0}
            for tid, cwes in items.items():
                findings = [f for f in per_target.get(tid, {}).get(tool, [])]
                row = classify_item(findings, cwes)
                for k in agg:
                    agg[k] += row[k]
            row = prf(agg["tp"], agg["fp"], agg["fn"])
            row.update(n_items=agg["n_items"], items_hit=agg["items_hit"],
                       recall_items=_j(agg["items_hit"] / agg["n_items"]) if agg["n_items"] else None,
                       seconds=_j(seconds.get(tool)))
            metrics[tool] = row
        mode = "items"

    result = {
        "kind": kind, "mode": mode,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tools": tools, "targets": {tid: rec.get("host_url") for tid, rec in sorted(targets.items())},
        "coverage": coverage, "metrics": metrics,
        "scan_timeout_s": cfg.scan_timeout_s,
    }
    paths.results.mkdir(parents=True, exist_ok=True)
    (paths.results / "dast_metrics.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False), encoding="utf-8")
    report = write_report(kind, paths, result)
    return report


def write_report(kind: str, paths: Paths, result: dict) -> Path:
    lines = [f"# DAST benchmark — {result['kind']}", "",
             f"*generated: {result['generated_at']} · tools: {', '.join(result['tools']) or '—'} · "
             f"targets: {len(result['targets'])} · лимит: {result['scan_timeout_s']} c на тул/цель*", ""]
    if result["mode"] == "owasp":
        lines += ["| tool | TP | FP | FN | Precision | Recall | F1 | TP-rate | FP-rate | cwe-agree | non-test | время |",
                  "|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for tool, m in sorted(result["metrics"].items()):
            lines.append(f"| {tool} | {m['tp']} | {m['fp']} | {m['fn']} | {_pct(m['precision'])} | "
                         f"{_pct(m['recall'])} | {_pct(m['f1'])} | {_pct(m.get('tp_rate'))} | "
                         f"{_pct(m.get('fp_rate'))} | {_pct(m.get('cwe_agreement'))} | "
                         f"{m.get('non_test_findings', '–')} | {_fmt_seconds(m.get('seconds'))} |")
        lines += ["", "TP/FP — по тест-кейсам OWASP Benchmark (URL -> BenchmarkTestNNNNN -> "
                      "expectedresults CSV); non-test — находки вне тестовых URL (учтены в FP).", ""]
    else:
        lines += ["| tool | items | hit | Recall(items) | TP(findings) | FP | Precision | время |",
                  "|---|---|---|---|---|---|---|---|"]
        for tool, m in sorted(result["metrics"].items()):
            lines.append(f"| {tool} | {m.get('n_items', '–')} | {m.get('items_hit', '–')} | "
                         f"{_pct(m.get('recall_items'))} | {m['tp']} | {m['fp']} | "
                         f"{_pct(m['precision'])} | {_fmt_seconds(m.get('seconds'))} |")
        lines += ["", "hit — приложение, где нашлась хотя бы одна находка с пересекающимся CWE "
                      "(match.py, cwe_overlap); TP/FP — отдельные находки.", ""]
    cov = result.get("coverage") or {}
    if cov:
        lines += ["", "## Coverage", ""]
        for tool, counts in sorted(cov.items()):
            pretty = ", ".join(f"{n} {k}" for k, n in sorted(counts.items())) or "не запускался"
            lines.append(f"- {tool}: {pretty}")
    out = paths.results / "dast_report.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


def _fmt_seconds(v) -> str:
    if v is None:
        return "–"
    v = int(v)
    return f"{v // 60}м{v % 60:02d}с" if v >= 60 else f"{v}с"


def _pct(v) -> str:
    return f"{v:.0%}" if v is not None else "–"


# --------------------------------------------------------------------------- loaders


def _read_state(paths: Paths) -> dict:
    f = paths.dast / "targets.json"
    return io.read_json(f) if f.is_file() else {}


def _owasp_gt(paths: Paths, kind: str):
    """Per-test labels from the pinned snapshot worktree's expectedresults CSV."""
    items = io.read_jsonl(paths.benchmark)
    if not items:
        raise SystemExit(f"{kind}: benchmark.jsonl is empty (run bench external build {kind})")
    first = items[0]
    worktree = paths.snapshots / "_groups" / _group_id(first["repo_url"], first["vuln_commit"])
    csv = getattr(load_external_config(), kind.replace("-", "_")).csv
    return owasp_tests((worktree / csv).read_text(encoding="utf-8-sig").splitlines())


def _items_cwes(paths: Paths, live: list[str]) -> dict[str, list[str]]:
    """CWE ranking per *live* item (boot-failed targets are not scored)."""
    all_items = {row["id"]: row["cwe"] for row in io.read_jsonl(paths.benchmark)}
    return {tid: all_items[tid] for tid in live if tid in all_items}
