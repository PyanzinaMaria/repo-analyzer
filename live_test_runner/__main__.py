"""CLI entry: python -m live_test_runner --profile smoke."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from .pipeline import PROFILES, run_pipeline


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Live HTTP sequence runner with Q-learning and genetic search",
    )
    parser.add_argument(
        "--profile",
        choices=tuple(PROFILES),
        default=os.environ.get("RUNNER_PROFILE", "smoke"),
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("TARGET_URL", "http://127.0.0.1:8080"),
    )
    parser.add_argument(
        "--start-path",
        default=os.environ.get("TARGET_START_PATH", "/"),
        help="Path opened at the start of each episode",
    )
    parser.add_argument("--budget", type=int, default=None)
    parser.add_argument("--horizon", type=int, default=None)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Defaults to live_test_runner/output/<profile>",
    )
    args = parser.parse_args(argv)
    report = run_pipeline(
        args.base_url,
        profile=args.profile,
        output_dir=args.output_dir,
        budget=args.budget,
        horizon=args.horizon,
        start_path=args.start_path,
    )
    agg = report["aggregates"]
    print(
        f"problems_total={agg['problems_total']} "
        f"problems_unique={agg['problems_unique']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
