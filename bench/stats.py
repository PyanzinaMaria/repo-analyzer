"""results/benchmark_stats.md: counts by language x CWE x split, LOC distribution, GT summary."""

from __future__ import annotations

import statistics
from collections import Counter
from pathlib import Path

from app.core import io
from bench.schemas import BenchmarkItem
from bench.config import Paths, load_benchmark_config

SPLITS = ["dev", "test", "post_cutoff", "extra"]
SOURCE_LINKS = {
    "patcheval": "[bytedance/PatchEval](https://github.com/bytedance/PatchEval)",
    "secbenchjs": "[cristianstaicu/SecBench.js](https://github.com/cristianstaicu/SecBench.js)",
    "pyvul": "[billquan/PyVul](https://github.com/billquan/PyVul)",
    "osv": "[osv.dev](https://osv.dev)",
}


def _md_table(header: list[str], rows: list[list]) -> list[str]:
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(str(x) for x in r) + " |" for r in rows]
    return out


def _pct(values: list[int], q: float) -> int:
    if not values:
        return 0
    s = sorted(values)
    return s[min(len(s) - 1, int(round(q * (len(s) - 1))))]


def write_stats(paths: Paths | None = None, extra_out: Path | None = None) -> Path:
    paths = paths or Paths()
    cfg = load_benchmark_config()
    items = [BenchmarkItem.model_validate(x) for x in io.read_jsonl(paths.benchmark)]
    lines = ["# Benchmark statistics", "", f"Items: **{len(items)}** "
             f"(validated against the `BenchmarkItem` schema).", ""]

    lines += ["## Items by split and language", ""]
    langs = sorted({it.language for it in items})
    rows = []
    for sp in SPLITS:
        c = Counter(it.language for it in items if it.split == sp)
        rows.append([sp] + [c.get(lg, 0) for lg in langs] + [sum(c.values())])
    rows.append(["**total**"] + [sum(1 for it in items if it.language == lg) for lg in langs] + [len(items)])
    lines += _md_table(["split"] + langs + ["total"], rows) + [""]

    lines += ["## Primary CWE x language x split", ""]
    cwes = [c for c in cfg.cwe_whitelist if any(it.cwe and it.cwe[0] == c for it in items)]
    header = ["CWE"] + [f"{sp}/{'py' if lg == 'python' else lg[:2]}" for sp in SPLITS for lg in ("python", "js")]
    rows = []
    for cwe in cwes:
        row = [cwe]
        for sp in SPLITS:
            for fam in ("python", "js"):
                row.append(sum(1 for it in items if it.split == sp and it.cwe[0] == cwe
                               and (it.language == "python") == (fam == "python")))
        rows.append(row)
    lines += _md_table(header, rows) + [""]
    main = [it for it in items if it.split in ("dev", "test")]
    if main:
        top = Counter(it.cwe[0] for it in main).most_common(1)[0]
        lines += [f"Largest CWE share in dev+test: {top[0]} = {top[1]}/{len(main)} "
                  f"({100 * top[1] / len(main):.0f}%; cap {100 * cfg.target.max_cwe_share:.0f}% per language).", ""]

    lines += ["## LOC distribution (in-scope source lines)", ""]
    rows = []
    for sp in SPLITS + ["all"]:
        for lg in langs:
            v = [it.loc for it in items if it.language == lg and (sp == "all" or it.split == sp)]
            if v:
                rows.append([sp, lg, len(v), min(v), _pct(v, 0.25), int(statistics.median(v)), _pct(v, 0.75), max(v)])
    lines += _md_table(["split", "language", "n", "min", "p25", "median", "p75", "max"], rows) + [""]

    lines += ["## Ground truth", ""]
    kinds = Counter(loc.kind for it in items for loc in it.gt_locations)
    fn_hunks = [loc for it in items for loc in it.gt_locations if loc.kind == "fix_hunk"]
    module_level = sum(1 for loc in fn_hunks if loc.function is None)
    pure_add = sum(1 for loc in fn_hunks if loc.pure_addition)
    long_fn = sum(1 for loc in fn_hunks if loc.function_start and loc.function_end
                  and loc.function_end - loc.function_start + 1 > 300)
    lines += _md_table(["metric", "value"], [
        ["GT locations by kind", ", ".join(f"{k}: {v}" for k, v in sorted(kinds.items()))],
        ["fix hunks at module level (no enclosing function)", f"{module_level}/{len(fn_hunks)}"],
        ["pure-addition hunks (anchored)", f"{pure_add}/{len(fn_hunks)}"],
        ["hunks in functions > 300 lines", f"{long_fn}/{len(fn_hunks)}"],
        ["median files changed (in scope)", int(statistics.median([it.files_changed for it in items])) if items else 0],
        ["median lines changed (in scope)", int(statistics.median([it.lines_changed for it in items])) if items else 0],
        ["items with PoC (has_poc)", sum(it.has_poc for it in items)],
        ["items with CVE id", sum(1 for it in items if it.cve)],
        ["items with published date", sum(1 for it in items if it.published)],
        ["tangled (extra split only)", sum(it.quality.tangled for it in items)],
        ["manually checked", sum(it.quality.manually_checked for it in items)],
    ]) + [""]

    checked = [it for it in items if it.quality.manually_checked and it.quality.label_ok is not None]
    if checked:
        ok = sum(1 for it in checked if it.quality.label_ok)
        lines += [f"Label accuracy estimate from manual check: {ok}/{len(checked)} = {100 * ok / len(checked):.0f}%.", ""]
    else:
        lines += ["Label accuracy: manual check not done yet (`python -m bench bench manual-sample`).", ""]

    lines += ["## Sources", ""]
    src = Counter(s for it in items for s in it.sources)
    lines += _md_table(["source", "link", "items (an item may have several)"],
                       [[s, SOURCE_LINKS.get(s, ""), n] for s, n in sorted(src.items())]) + [""]

    lines += ["## Items", ""]
    rows = []
    for it in items:
        repo = it.repo_url.split("github.com/")[-1]
        adv = (f"[{it.cve}](https://nvd.nist.gov/vuln/detail/{it.cve})" if it.cve else
               f"[{it.ghsa}](https://github.com/advisories/{it.ghsa})" if it.ghsa else "-")
        cwe = it.cwe[0]
        cwe_md = f"[{cwe}](https://cwe.mitre.org/data/definitions/{cwe[4:]}.html)" if cwe[4:].isdigit() else cwe
        rows.append([f"`{it.id}`", it.split, it.language, cwe_md, adv, f"[{repo}]({it.repo_url})",
                     f"[`{it.fix_commit[:8]}`]({it.repo_url}/commit/{it.fix_commit})", f"{it.loc:,}",
                     ", ".join(it.sources)])
    lines += _md_table(["id", "split", "language", "CWE", "advisory", "repository", "fix", "LOC", "sources"], rows)
    lines.append("")

    out = paths.results / "benchmark_stats.md"
    io.atomic_write_text(out, "\n".join(lines))
    if extra_out is not None:
        io.atomic_write_text(Path(extra_out), "\n".join(lines))
    return out
