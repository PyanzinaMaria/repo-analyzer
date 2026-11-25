"""`semgrep --test` over the generated rules and the snippets in config/llmflow/tests/.

Each snippet file is tested against the rule family its name starts with, so annotations only have to
cover that family: callsite_*.py → call-site rules, flows*.py → taint rules (o2s/i2p/par),
gates*.py → gate rules, hygiene*.py → hygiene rules, sources*.py → source search rules.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from app.llmflow.catalog import LLMFLOW_DIR, Catalog, load_catalog
from app.llmflow.rulegen import static_rules, write_rules
from app.llmflow.semgrep import run_test

FAMILIES = {"callsite": ("callsite",), "flows": ("o2s", "i2p", "par"), "gates": ("gate",),
            "hygiene": ("hygiene",), "sources": ("src",)}


def build_test_dir(dest: Path, cat: Catalog | None = None, tests_dir: Path = LLMFLOW_DIR / "tests") -> list[str]:
    cat = cat or load_catalog()
    rules = static_rules(cat)
    names = []
    for snippet in sorted(tests_dir.glob("*.py")):
        prefix = snippet.stem.split("_")[0]
        fams = FAMILIES.get(prefix)
        if not fams:
            continue
        subset = [r for r in rules if r.get("metadata", {}).get("family") in fams]
        # one directory per pair: `semgrep --test` runs the configs of a directory in parallel processes,
        # which race on semgrep's settings file on Windows
        d = dest / snippet.stem
        d.mkdir(parents=True, exist_ok=True)
        write_rules(subset, d / f"{snippet.stem}.yaml")
        shutil.copy2(snippet, d / snippet.name)
        names.append(snippet.stem)
    return names


def run_rule_tests(keep: Path | None = None) -> tuple[bool, str, list[str]]:
    tmp = Path(tempfile.mkdtemp(prefix="llmflow-test-")) if keep is None else keep
    tmp.mkdir(parents=True, exist_ok=True)
    try:
        names = build_test_dir(tmp)
        ok, outs = True, []
        for name in names:
            rc, out = run_test(tmp / name)
            ok = ok and rc == 0
            outs.append(f"== {name}: {'ok' if rc == 0 else 'FAILED'}\n{out.strip()}")
        return ok, "\n".join(outs), names
    finally:
        if keep is None:
            shutil.rmtree(tmp, ignore_errors=True)
