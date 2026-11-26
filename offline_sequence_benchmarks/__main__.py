"""Run the complete offline benchmark suite."""

import argparse
from pathlib import Path

from . import html_fixture, synthetic, tuning


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("smoke", "full"), default="smoke")
    parser.add_argument("--horizon", type=int, default=synthetic.HORIZON,
                        help="Maximum actions per episode (default: %(default)s)")
    parser.add_argument("--output-dir", type=Path,
                        default=Path(__file__).resolve().parent / "output")
    args = parser.parse_args(argv)
    if args.horizon < 1:
        parser.error("--horizon must be positive")
    # Keep smoke data separate from full runs, even if the same path is used.
    output = args.output_dir / args.profile
    output.mkdir(parents=True, exist_ok=True)
    smoke = args.profile == "smoke"
    horizon = ["--horizon", str(args.horizon)]
    print(f"Offline benchmark: {args.profile}; episode limit: {args.horizon}; "
          f"results: {output.resolve()}", flush=True)

    print("\nSynthetic state machine", flush=True)
    synthetic.main(horizon + ["--csv", str(output / "sequence_search_results.csv")]
                   + (["--seeds", "2", "--budget", "96"] if smoke else []))
    print("\nDynamic HTML fixture", flush=True)
    html_fixture.main(horizon + ["--csv", str(output / "html_sequence_results.csv"),
                       "--graph-json", str(output / "html_sequence_graphs.json"),
                       "--graph-seed", "0" if smoke else "8"]
                      + (["--seeds", "2", "--budget", "96"] if smoke else []))
    print("\nTuning and hybrid comparison", flush=True)
    tuning.main(horizon + ["--hybrids", "--output-dir", str(output)]
                + (["--candidates", "3", "--dev", "3", "--test", "3",
                    "--budget", "96"] if smoke else []))


if __name__ == "__main__":
    main()
