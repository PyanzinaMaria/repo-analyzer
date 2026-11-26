from __future__ import annotations

"""Security pipeline CLI.

    python -m app.security review --repo PATH [--no-llm]
    python -m app.security scan   --repo PATH [--url http://host:port] [--no-llm] [--allow-private]
    python -m app.security verify --repo PATH --url URL --hypotheses hypotheses.json
"""

import argparse
import json
import sys
from pathlib import Path

from app.security.config import load_security_config
from app.security.models import SecurityRun, VulnHypothesis
from app.security.pipeline import run_security_scan, top_risks
from app.security.report import write_reports


def _summary(run: SecurityRun) -> None:
    meta = run.meta
    print(f"repo      : {run.repo}")
    print(f"target    : {run.target_url or '—'}")
    print(f"review    : {meta.get('mode')} "
          f"({(meta.get('review') or {}).get('hypotheses', 0)} гипотез, "
          f"файлов {(meta.get('review') or {}).get('files', 0)})")
    llm_info = (meta.get("review") or {}).get("llm") or {}
    if llm_info:
        print(f"llm       : {llm_info.get('provider')} / {llm_info.get('model')} "
              f"[key: {'yes' if llm_info.get('key') else 'no'}]")
    if (meta.get("review") or {}).get("llm_error"):
        print(f"llm error : {(meta.get('review') or {}).get('llm_error')[:160]}")
    print(f"hypotheses: {meta.get('hypotheses', 0)} "
          f"(sast {meta.get('from_sast', 0)})")
    ver = meta.get("verification") or {}
    print(f"verdicts  : confirmed {meta.get('confirmed', 0)}, refuted {meta.get('refuted', 0)}, "
          f"uncertain {meta.get('uncertain', 0)}, skipped {meta.get('skipped', 0)} "
          f"[{ver.get('plans', 0)} проверок, {ver.get('requests', 0)} запросов]")
    risks = top_risks(run, 10)
    if risks:
        print("top risks :")
        for r in risks:
            print(f"  {r['priority']} [{r['severity']}] {r['class']:22s} {r['file'] or '—':40s} {r['url'] or ''}")
    print(f"findings  : {len(run.findings)}")


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass
    import os
    if os.getenv("SECURITY_DEBUG", "").lower() in {"1", "true", "yes", "on"}:
        import logging
        logging.basicConfig(level=logging.INFO,
                            format="%(levelname)s %(name)s: %(message)s")
    ap = argparse.ArgumentParser(prog="app.security", description="Code review -> hypotheses -> pentest")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--repo", required=True)
        p.add_argument("--url", default=None)
        p.add_argument("--no-llm", action="store_true", help="не использовать LLM (детерминированный режим)")
        p.add_argument("--llm-provider", default=None,
                       help="groq | gigachat | openrouter | gemini | ollama")
        p.add_argument("--llm-model", default=None, help="переопределить модель провайдера")
        p.add_argument("--llm-base-url", default=None, help="переопределить base_url")
        p.add_argument("--allow-private", action="store_true", help="разрешить localhost/RFC1918")
        p.add_argument("--auth-user", default=None, help="логин для защищённых эндпоинтов")
        p.add_argument("--auth-pass", default=None, help="пароль")
        p.add_argument("--auth-login-url", default="/login")
        p.add_argument("--auth-register-url", default=None,
                       help="эндпоинт регистрации (создать пользователя перед логином)")
        p.add_argument("--out", default="data/security")
        p.add_argument("--json", action="store_true")

    p_review = sub.add_parser("review", help="только ревью кода (гипотезы)")
    common(p_review)
    p_scan = sub.add_parser("scan", help="ревью + динамическая проверка")
    common(p_scan)
    p_verify = sub.add_parser("verify", help="проверка готовых гипотез")
    common(p_verify)
    p_verify.add_argument("--hypotheses", required=True, help="JSON со списком гипотез")

    args = ap.parse_args(argv)
    repo = Path(args.repo)
    if not repo.exists():
        print(f"[FAIL] репозиторий не найден: {repo}")
        return 2

    overrides = {
        "verify_allow_private": True if args.allow_private else None,
        "llm_enabled": False if args.no_llm else None,
        "llm_provider": args.llm_provider,
        "llm_model": args.llm_model,
        "llm_base_url": args.llm_base_url,
        "review_enabled": True,
        "auth_enabled": bool(args.auth_user),
        "auth_username": args.auth_user,
        "auth_password": args.auth_pass,
        "auth_login_url": args.auth_login_url,
        "auth_register_url": args.auth_register_url,
    }
    cfg = None
    try:
        cfg = load_security_config({k: v for k, v in overrides.items() if v is not None})
    except ValueError as exc:
        print(f"[FAIL] конфигурация LLM: {exc}")
        return 2

    if args.cmd == "review":
        run = run_security_scan(repo, None, cfg=cfg, use_llm=not args.no_llm)
    elif args.cmd == "verify":
        data = json.loads(Path(args.hypotheses).read_text(encoding="utf-8"))
        raw = data.get("hypotheses", data) if isinstance(data, dict) else data
        hypotheses = [VulnHypothesis(**h) for h in raw]
        from app.security.models import SecurityRun as SR
        from app.security.verifier import Verifier, verifications_to_findings

        verifier = Verifier(args.url, cfg)
        verifications = verifier.verify(hypotheses)
        run = SR(repo=str(repo), target_url=args.url, hypotheses=hypotheses,
                 verifications=verifications,
                 findings=verifications_to_findings(verifications, hypotheses),
                 meta={"mode": "verify-only", "hypotheses": len(hypotheses),
                       "confirmed": verifier.stats.confirmed, "refuted": verifier.stats.refuted,
                       "uncertain": verifier.stats.uncertain, "skipped": verifier.stats.skipped,
                       "verification": {"status": "ok", **verifier.stats.as_dict()}})
    else:
        run = run_security_scan(repo, args.url, cfg=cfg, use_llm=not args.no_llm,
                                language=None)

    paths = write_reports(run, Path(args.out))
    if args.json:
        print(json.dumps([f.model_dump(mode="json") for f in run.findings],
                         indent=2, ensure_ascii=False))
    else:
        _summary(run)
    print(f"report    : {paths['markdown']}")
    print(f"json      : {paths['json']}")
    print(f"sarif     : {paths['sarif']}")

    # explicit failure signals for the dynamic stage
    vmeta = run.meta.get("verification") or {}
    if args.url:
        if vmeta.get("status") == "failed":
            print(f"[FAIL] динамическая проверка не выполнена: {vmeta.get('error')}")
            if "blocked" in str(vmeta.get("error", "")):
                print("       цель приватная — добавьте --allow-private")
            return 2
        if vmeta.get("status") == "ok" and not vmeta.get("ok_responses"):
            print("[FAIL] ни один запрос не дошёл до цели — проверьте URL и что приложение запущено")
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
