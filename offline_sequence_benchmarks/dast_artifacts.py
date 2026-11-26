"""Summarize finished DAST exports and recorded functional coverage offline."""

import argparse
import json
from collections import Counter
from collections.abc import Mapping
from pathlib import Path


MAX_JSON_BYTES = 16 * 1024 * 1024
RISK_LEVELS = {
    "0": "informational", "1": "low", "2": "medium", "3": "high",
}
DAST_STATUSES = {
    "ok": "completed", "success": "completed", "succeeded": "completed",
    "completed": "completed", "partial": "partial", "failed": "failed",
    "error": "failed", "skipped": "skipped",
}


def _metadata(meta):
    """Return a canonical status, or None when dynamic was not selected."""
    if not isinstance(meta, Mapping):
        raise ValueError("Expected a metadata object")
    runners = meta.get("runners")
    if runners is None:
        return None
    if not isinstance(runners, (tuple, list)) or not all(isinstance(r, str) for r in runners):
        raise ValueError("Expected a list of runner names")
    if "dynamic" not in runners:
        return None
    dast = meta.get("dast")
    status = dast.get("status") if isinstance(dast, Mapping) else None
    return DAST_STATUSES.get(status.strip().lower(), "unknown") if isinstance(status, str) else "unknown"


def _zap_counts(report):
    """Count alert groups per site and severity, not confirmed vulnerabilities."""
    if not isinstance(report, dict) or not isinstance(report.get("site"), list):
        raise ValueError("Expected a ZAP report with a site array")
    levels = dict.fromkeys((*RISK_LEVELS.values(), "unknown"), 0)
    for site in report["site"]:
        if not isinstance(site, dict) or not isinstance(site.get("alerts"), list):
            raise ValueError("Expected an alerts array per site")
        for alert in site["alerts"]:
            if not isinstance(alert, dict) or "riskcode" not in alert:
                raise ValueError("Expected riskcode in each alert")
            code = alert["riskcode"]
            risk = RISK_LEVELS.get(str(code), "unknown") if type(code) in (str, int) else "unknown"
            levels[risk] += 1
    return {"sites": len(report["site"]), "alert_groups": sum(levels.values()), "by_risk": levels}


def _coverage(trace, *, include_graph=False):
    if (not isinstance(trace, dict) or type(trace.get("schema_version")) is not int
            or trace["schema_version"] != 1 or not isinstance(trace.get("episodes"), list)):
        raise ValueError("Expected a version 1 coverage trace with an episodes array")
    states, starts, transitions = set(), set(), Counter()
    steps, longest = 0, 0
    for episode in trace["episodes"]:
        if not isinstance(episode, list) or not episode:
            raise ValueError("Expected each episode to be a nonempty array")
        previous = None
        for edge in episode:
            if (not isinstance(edge, list) or len(edge) != 3
                    or any(type(value) is not int or value < 0 for value in edge)):
                raise ValueError("Expected three nonnegative integer IDs per transition")
            source, action, target = edge
            if previous is not None and source != previous:
                raise ValueError("Consecutive transitions must join within an episode")
            if previous is None:
                starts.add(source)
            states.update((source, target))
            transitions[source, action, target] += 1
            previous = target
        steps += len(episode)
        longest = max(longest, len(episode))
    summary = {"episodes": len(trace["episodes"]), "steps": steps,
               "observed_states": len(states), "unique_transitions": len(transitions),
               "longest_episode": longest}
    if include_graph:
        summary["graph"] = {
            "states": sorted(states),
            "start_states": sorted(starts),
            "edges": [
                {"source": source, "action": action, "target": target, "observations": count}
                for (source, action, target), count in sorted(transitions.items())
            ],
        }
    return summary


def build_observed_graph(trace: dict) -> dict:
    """Build a directed graph of only the transitions in a finished local trace."""
    return {"schema_version": 1, **_coverage(trace, include_graph=True)}


def _read_json(path):
    if not path.is_file():
        if not path.exists():
            raise FileNotFoundError(path)
        raise ValueError("Expected a regular JSON file")
    with path.open("rb") as handle:
        data = handle.read(MAX_JSON_BYTES + 1)
    if len(data) > MAX_JSON_BYTES:
        raise ValueError("JSON artifact exceeds the size limit")
    return json.loads(data.decode("utf-8-sig"))


def _collect(path, summarize):
    if path is None:
        return {"status": "not_provided"}
    try:
        return {"status": "available", **summarize(_read_json(Path(path)))}
    except FileNotFoundError:
        return {"status": "missing"}
    except OSError:
        return {"status": "unreadable"}
    except (ValueError, RecursionError):
        return {"status": "invalid"}


def summarize_artifacts(
    meta: Mapping[str, object], *, zap_report: Path | str | None = None,
    coverage_trace: Path | str | None = None,
) -> dict | None:
    """Read local exports from the same finished scan; never modify supplied metadata."""
    status = _metadata(meta)
    if status is None:
        return None
    if status not in ("completed", "partial"):
        return {"schema_version": 1, "dast_status": status,
                "zap": {"status": "not_read"}, "coverage": {"status": "not_read"}}
    return {"schema_version": 1, "dast_status": status,
            "zap": _collect(zap_report, _zap_counts),
            "coverage": _collect(coverage_trace, _coverage)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--meta", type=Path, help="JSON object containing ScanResult.meta")
    mode.add_argument("--graph-from-trace", type=Path, help="Build a graph from a local recorded trace")
    parser.add_argument("--zap-report", type=Path, help="Local traditional JSON report")
    parser.add_argument("--coverage-trace", type=Path, help="Local recorded coverage trace")
    args = parser.parse_args(argv)
    if args.graph_from_trace is not None:
        if args.zap_report is not None or args.coverage_trace is not None:
            parser.error("--graph-from-trace is standalone")
        try:
            graph = build_observed_graph(_read_json(args.graph_from_trace))
        except (OSError, ValueError, RecursionError):
            parser.error("--graph-from-trace must point to a readable, valid version 1 coverage trace")
        print(json.dumps(graph, indent=2))
        return
    try:
        summary = summarize_artifacts(
            _read_json(args.meta), zap_report=args.zap_report, coverage_trace=args.coverage_trace,
        )
    except (OSError, ValueError, RecursionError):
        parser.error("--meta must be a readable JSON metadata object with a valid runners list")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
