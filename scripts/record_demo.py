"""Record a CLI demo as an asciinema v2 cast: types the command, runs it for real (with colors),
and streams its output with real timing (long pauses compressed). Convert to GIF with `agg`.

    python scripts/record_demo.py docs/casts/audit.cast --show "python -m bench audit show X" -- scripts/sb audit show X
    agg --font-family "DejaVu Sans Mono" docs/casts/audit.cast docs/img/audit.gif
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from pathlib import Path

PROMPT = "\x1b[1;32m❯\x1b[0m "


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--show", required=True, help="command text to type on screen")
    ap.add_argument("--width", type=int, default=110)
    ap.add_argument("--height", type=int, default=40)
    ap.add_argument("--line-delay", type=float, default=0.0, help="min delay between output lines (scroll effect)")
    ap.add_argument("--max-gap", type=float, default=1.2, help="cap for pauses in the real output")
    ap.add_argument("--hold", type=float, default=4.0, help="seconds to hold the final screen")
    import sys

    argv = sys.argv[1:]
    if "--" not in argv:
        ap.error("pass the command to run after --")
    split = argv.index("--")
    a = ap.parse_args(argv[:split])
    cmd = argv[split + 1:]

    events: list[list] = []
    t = 0.5
    events.append([t, "o", PROMPT])
    for ch in a.show:                       # typing
        t += 0.035 if ch != " " else 0.06
        events.append([round(t, 3), "o", ch])
    t += 0.5
    events.append([round(t, 3), "o", "\r\n"])

    env = {**os.environ, "FORCE_COLOR": "1", "COLUMNS": str(a.width), "LINES": str(a.height),
           "TERM": "xterm-256color", "PYTHONUNBUFFERED": "1"}
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    last = time.monotonic()
    assert proc.stdout is not None
    for raw in iter(proc.stdout.readline, b""):
        now = time.monotonic()
        t += max(a.line_delay, min(now - last, a.max_gap))
        last = now
        line = raw.decode("utf-8", "replace").rstrip("\n")
        events.append([round(t, 3), "o", line + "\r\n"])
    proc.wait()
    t += 0.3
    events.append([round(t, 3), "o", PROMPT])
    events.append([round(t + a.hold, 3), "o", " "])

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    header = {"version": 2, "width": a.width, "height": a.height, "timestamp": int(time.time()),
              "env": {"TERM": "xterm-256color", "SHELL": "/bin/bash"}}
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(header) + "\n")
        for e in events:
            fh.write(json.dumps(e, ensure_ascii=False) + "\n")
    print(f"{out}: {len(events)} events, {t + a.hold:.1f}s, exit {proc.returncode}")


if __name__ == "__main__":
    main()
