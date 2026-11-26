from __future__ import annotations

"""CLI: run the pentest agent against a live target.

    python -m app.dast.agent --url http://127.0.0.1:5001 --no-llm --allow-private
    python -m app.dast.agent --url https://example.com            # LLM planner
"""
import argparse
import json
import sys
from pathlib import Path

from app.dast.agent.agent import run_pentest
from app.dast.agent.report import write_report


def main(argv: list[str] | None = None) -> int:
    try:  # Windows console defaults to cp1251; keep Russian output readable
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass
    ap = argparse.ArgumentParser(description="Pentest agent (DAST)")
    ap.add_argument("--url", required=True, help="target base URL")
    ap.add_argument("--no-llm", action="store_true", help="deterministic plan, no API calls")
    ap.add_argument("--allow-private", action="store_true", help="allow localhost/RFC1918 targets")
    ap.add_argument("--max-steps", type=int, default=None)
    ap.add_argument("--max-seconds", type=int, default=None)
    ap.add_argument("--max-requests", type=int, default=None)
    ap.add_argument("--out", default=None, help="report directory (default: data/dast/pentest)")
    ap.add_argument("--json", action="store_true", help="print findings as JSON")
    args = ap.parse_args(argv)

    overrides = {
        "allow_private_targets": True if args.allow_private else None,
        "max_steps": args.max_steps,
        "max_seconds": args.max_seconds,
        "max_requests": args.max_requests,
    }
    run = None
    try:
        run = run_pentest(args.url, use_llm=not args.no_llm, overrides=overrides)
    except Exception as exc:  # noqa: BLE001 - report the failure, do not dump a traceback
        print(f"[FAIL] агент не смог стартовать: {type(exc).__name__}: {exc}")
        if "blocked" in str(exc) or "private" in str(exc) or "loopback" in str(exc):
            print("       цель приватная/локальная — добавьте --allow-private")
        elif "Connect" in str(exc) or "refused" in str(exc):
            print("       цель недоступна — проверьте, что приложение запущено и порт открыт")
        return 2

    out = Path(args.out) if args.out else Path("data/dast/pentest")
    md, js = write_report(run, out)

    if args.json:
        print(json.dumps([f.model_dump(mode="json") for f in run.findings],
                         indent=2, ensure_ascii=False))
    else:
        print(f"target : {run.target_url}")
        print(f"mode   : {run.mode}")
        print(f"stats  : {run.stats}")
        print(f"pages  : {run.pages}")
        if not run.stats.get("ok_responses"):
            print("[FAIL] ни один запрос не дошёл до цели — проверьте URL и что приложение запущено")
            return 2
        print(f"findings ({len(run.findings)}):")
        for f in run.findings:
            extra = f.extra or {}
            print(f"  - [{f.severity.value}] {f.title} ({f.cwe}) {extra.get('url')}")
            if extra.get("payload"):
                print(f"      payload: {extra['payload']}")
        print(f"report : {md}")
    if not run.findings:
        print("[OK] цель доступна, но подтверждённых находок нет "
              "(это не ошибка; см. отчёт и раздел ограничений)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
