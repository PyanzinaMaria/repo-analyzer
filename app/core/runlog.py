"""Per-command run summary and environment recording."""

from __future__ import annotations

import logging
import platform
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from app.core import io

console = Console(stderr=True)
log = logging.getLogger("secaudit")


def setup_logging(verbose: bool = False) -> None:
    if log.handlers:
        return
    handler = RichHandler(console=console, show_path=False, markup=False, rich_tracebacks=True)
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, handlers=[handler],
                        format="%(message)s", datefmt="%H:%M:%S")


class RunSummary:
    """Collects counters for one CLI command and prints a short table at the end."""

    def __init__(self, title: str):
        self.title = title
        self.counts: Counter[str] = Counter()
        self.failures: list[str] = []
        self.cost_usd = 0.0
        self.notes: list[str] = []
        self._t0 = time.monotonic()

    def __enter__(self) -> "RunSummary":
        return self

    def __exit__(self, *exc) -> None:
        self.print()

    def inc(self, key: str, n: int = 1) -> None:
        self.counts[key] += n

    def fail(self, what: str) -> None:
        self.counts["failed"] += 1
        self.failures.append(what)

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self._t0

    def print(self) -> None:
        console.print(f"[bold]{self.title}[/]", highlight=False)
        t = Table(show_header=False)
        for k, v in self.counts.items():
            t.add_row(k, str(v))
        t.add_row("time", f"{self.elapsed:.1f}s")
        t.add_row("cost", f"${self.cost_usd:.4f}")
        console.print(t)
        for f in self.failures[:20]:
            console.print(f"  [red]fail[/red] {f}")
        if len(self.failures) > 20:
            console.print(f"  ... and {len(self.failures) - 20} more failures")
        for n in self.notes:
            console.print(f"  {n}")


def _version(cmd: list[str]) -> str | None:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        text = (out.stdout or out.stderr).strip().splitlines()
        return text[0] if text else None
    except Exception:  # noqa: BLE001 - best effort
        return None


def record_env(out: Path | None = None) -> dict:
    """Return analyzer/tool versions; also write them to `out` (e.g. results/env.json) if given."""
    from app.sast.tools import tool_versions

    env = {
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "git": _version(["git", "--version"]),
        "tools": tool_versions(),
    }
    if out is not None:
        io.write_json(out, env)
    return env
