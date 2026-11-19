"""Per-command run summary and environment recording.

Rich is optional: the web/worker path only needs logging + RunSummary counters.
CLI/bench use rich tables when the package is installed.
"""

from __future__ import annotations

import logging
import platform
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from app.core import io

log = logging.getLogger("secaudit")

try:
    from rich.console import Console
    from rich.logging import RichHandler
    from rich.table import Table

    console = Console(stderr=True)
    _HAS_RICH = True
except ImportError:  # pragma: no cover - optional for web runtime
    Console = None  # type: ignore[misc, assignment]
    RichHandler = None  # type: ignore[misc, assignment]
    Table = None  # type: ignore[misc, assignment]
    console = None
    _HAS_RICH = False


def setup_logging(verbose: bool = False) -> None:
    if log.handlers:
        return
    level = logging.DEBUG if verbose else logging.INFO
    if _HAS_RICH and RichHandler is not None and console is not None:
        handler = RichHandler(
            console=console, show_path=False, markup=False, rich_tracebacks=True
        )
        logging.basicConfig(
            level=level, handlers=[handler], format="%(message)s", datefmt="%H:%M:%S"
        )
    else:
        logging.basicConfig(
            level=level,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        )


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

    def bump(self, key: str, n: int = 1) -> None:
        self.inc(key, n)

    def fail(self, what: str) -> None:
        self.counts["failed"] += 1
        self.failures.append(what)

    def note(self, msg: str) -> None:
        self.notes.append(msg)

    def add_cost(self, usd: float) -> None:
        self.cost_usd += float(usd or 0.0)

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self._t0

    def print(self) -> None:
        if _HAS_RICH and console is not None and Table is not None:
            console.print(f"[bold]{self.title}[/]", highlight=False)
            t = Table(show_header=False)
            for k, v in self.counts.items():
                t.add_row(k, str(v))
            t.add_row("time", f"{self.elapsed:.1f}s")
            t.add_row("cost", f"${self.cost_usd:.4f}")
            console.print(t)
            for f in self.failures[:20]:
                console.print(f"  [red]fail[/red] {f}")
            for n in self.notes:
                console.print(f"  {n}")
        else:
            log.info(
                "%s done in %.1fs counts=%s cost=%.4f",
                self.title,
                self.elapsed,
                dict(self.counts),
                self.cost_usd,
            )

    def finish(self) -> dict:
        self.print()
        return {
            "title": self.title,
            "elapsed_s": round(self.elapsed, 2),
            "counts": dict(self.counts),
            "failures": list(self.failures),
            "cost_usd": round(self.cost_usd, 6),
            "notes": list(self.notes),
        }


def _version(cmd: list[str]) -> str | None:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        text = (out.stdout or out.stderr).strip().splitlines()
        return text[0] if text else None
    except Exception:  # noqa: BLE001 - best effort
        return None


def record_env(out: Path | None = None) -> dict:
    """Return analyzer/tool versions; also write them to `out` if given."""
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
