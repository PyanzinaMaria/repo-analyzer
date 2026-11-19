"""Manual ground-truth check (spec §3.5): sample test items, show their GT next to the fix diff."""

from __future__ import annotations

import random
from pathlib import Path

from app.core import io
from bench import git_utils as g
from bench.config import Paths


def write_manual_sample(fraction: float = 0.2, seed: int = 13, force: bool = False,
                        paths: Paths | None = None) -> Path:
    paths = paths or Paths()
    out = paths.results / "manual_check.md"
    items = io.read_jsonl(paths.benchmark)
    test = sorted((it for it in items if it["split"] == "test"), key=lambda it: it["id"])
    sample_file = paths.results / "manual_sample.json"
    if sample_file.exists() and not force:
        ids = io.read_json(sample_file)
    else:
        n = max(1, round(fraction * len(test)))
        ids = sorted(it["id"] for it in random.Random(seed).sample(test, min(n, len(test))))
        io.write_json(sample_file, ids)
    by_id = {it["id"]: it for it in items}
    lines = [
        "# Manual ground-truth check", "",
        f"Sample: {len(ids)} of {len(test)} test items (seed {seed}).", "",
        "For each item, check that the `gt_locations` point at the vulnerable code, i.e. the fix hunk "
        "really is the security fix, not refactoring. Then record the verdict:", "",
        "```bash", "scripts/sb bench mark-checked <id> --ok        # or --bad --note '...'", "```", "",
    ]
    for item_id in ids:
        it = by_id.get(item_id)
        if not it:
            continue
        status = ("✅" if it["quality"].get("label_ok") else "❌") if it["quality"].get("manually_checked") else "⬜"
        lines += [f"## {status} {it['id']}", "",
                  f"- repo: {it['repo_url']}  ",
                  f"- fix: {it['repo_url']}/commit/{it['fix_commit']}  ",
                  f"- CWE: {', '.join(it['cwe'])}; "
                  f"CVE: {('[' + it['cve'] + '](https://nvd.nist.gov/vuln/detail/' + it['cve'] + ')') if it.get('cve') else '-'}; "
                  f"GHSA: {('[' + it['ghsa'] + '](https://github.com/advisories/' + it['ghsa'] + ')') if it.get('ghsa') else '-'}  ",
                  f"- files/lines changed: {it['files_changed']}/{it['lines_changed']}", "",
                  "| kind | file | lines (vuln) | function (vuln) | lines (fixed) |", "|---|---|---|---|---|"]
        for loc in it["gt_locations"]:
            fixed = (f"{loc['fixed_start_line']}-{loc['fixed_end_line']}" if loc.get("fixed_start_line") else "-")
            lines.append(f"| {loc['kind']}{' (add)' if loc.get('pure_addition') else ''} | {loc['file']} | "
                         f"{loc['start_line']}-{loc['end_line']} | {loc.get('function') or '(module)'} | {fixed} |")
        gd = g.repo_dir(paths.repos, it["repo_url"])
        diff = ""
        if gd.exists():
            try:
                diff = g.git(["diff", "-U2", "--no-color", "--stat", "-p", it["vuln_commit"], it["fix_commit"]],
                             git_dir=gd, timeout=300).stdout
            except g.GitError:
                diff = ""
        if diff:
            if len(diff) > 6000:
                diff = diff[:6000] + "\n... (truncated)"
            lines += ["", "<details><summary>fix diff</summary>", "", "```diff", diff, "```", "", "</details>"]
        lines.append("")
    io.atomic_write_text(out, "\n".join(lines))
    return out


def mark_checked(item_id: str, ok: bool, note: str = "", paths: Paths | None = None) -> None:
    paths = paths or Paths()
    items = io.read_jsonl(paths.benchmark)
    found = False
    for it in items:
        if it["id"] == item_id:
            it["quality"]["manually_checked"] = True
            it["quality"]["label_ok"] = ok
            it["quality"]["note"] = note or None
            found = True
    if not found:
        raise SystemExit(f"unknown item id: {item_id}")
    io.write_jsonl(paths.benchmark, items)
