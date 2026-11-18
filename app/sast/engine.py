"""Static-analysis stage of a scan for one language: SAST tools + code context.

Used by the language handlers (app/languages/*). For a workspace it
  1. runs the configured SAST tools (Semgrep, Bandit, ESLint-security, CodeQL) on a temporary copy,
     normalizes their SARIF and merges near-duplicates across tools (app/sast/run.py);
  2. keeps findings in product code only (tests, examples, vendored code are dropped);
  3. builds the code context: tree-sitter index, call graph, entry points, sinks (app/context/build.py).

Each step soft-fails: a missing tool or a parse error is recorded in `meta` and the scan goes on.
"""

from __future__ import annotations

import logging
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from app.core import io
from app.core.yaml_configs import FAMILY, in_product_code, in_scope, compile_excludes, load_sast_config
from app.models.finding import Finding, Severity
from app.sast import tools as toolmod
from app.sast.normalize import MergedFinding, rank_sast
from app.sast.run import run_tools_isolated

logger = logging.getLogger(__name__)

DEFAULT_TOOLS = {"python": ["bandit", "semgrep", "codeql"], "javascript": ["eslint", "semgrep", "codeql"]}

CWE_TITLES_RU = {
    "CWE-22": "Обход пути (path traversal)", "CWE-78": "Внедрение команд ОС", "CWE-79": "Межсайтовый скриптинг (XSS)",
    "CWE-89": "SQL-инъекция", "CWE-94": "Внедрение кода", "CWE-95": "Внедрение кода через eval",
    "CWE-502": "Небезопасная десериализация", "CWE-611": "Внешние XML-сущности (XXE)",
    "CWE-918": "Подделка серверных запросов (SSRF)", "CWE-352": "Подделка межсайтовых запросов (CSRF)",
    "CWE-287": "Некорректная аутентификация", "CWE-862": "Отсутствие авторизации",
    "CWE-863": "Некорректная авторизация", "CWE-1321": "Загрязнение прототипа",
    "CWE-1333": "ReDoS (катастрофический бэктрекинг)", "CWE-601": "Открытое перенаправление",
    "CWE-20": "Недостаточная проверка входных данных", "CWE-798": "Учётные данные в коде",
    "CWE-327": "Слабый криптоалгоритм", "CWE-328": "Слабый хеш", "CWE-330": "Предсказуемые случайные значения",
    "CWE-295": "Отключённая проверка сертификата", "CWE-400": "Исчерпание ресурсов",
    "CWE-209": "Утечка информации в сообщениях об ошибках", "CWE-915": "Массовое присваивание",
}
REMEDIATION_RU = {
    "CWE-22": "Нормализуйте путь и проверяйте, что он остаётся внутри разрешённого каталога.",
    "CWE-78": "Не передавайте пользовательские данные в оболочку: список аргументов без shell=True, белый список.",
    "CWE-79": "Экранируйте вывод по контексту (HTML/атрибут/URL), используйте автоэкранирование шаблонов.",
    "CWE-89": "Используйте параметризованные запросы или ORM вместо конкатенации строк.",
    "CWE-94": "Не исполняйте код, построенный из входных данных; замените eval/exec безопасным разбором.",
    "CWE-95": "Не исполняйте код, построенный из входных данных; замените eval/exec безопасным разбором.",
    "CWE-502": "Не десериализуйте недоверенные данные pickle/yaml.load; используйте JSON или safe_load.",
    "CWE-611": "Отключите внешние сущности и DTD в XML-парсере (defusedxml).",
    "CWE-918": "Проверяйте целевые адреса по белому списку, запрещайте внутренние сети.",
    "CWE-1321": "Блокируйте ключи __proto__/constructor/prototype при слиянии объектов.",
    "CWE-1333": "Упростите регулярное выражение или ограничьте длину входа.",
    "CWE-601": "Разрешайте перенаправление только на относительные пути или адреса из белого списка.",
    "CWE-798": "Вынесите секреты в переменные окружения или хранилище секретов.",
    "CWE-327": "Используйте современные алгоритмы (AES-GCM, SHA-256 и выше).",
    "CWE-328": "Используйте современные алгоритмы (AES-GCM, SHA-256 и выше).",
}
_SEVERITY = {"critical": Severity.critical, "high": Severity.high, "medium": Severity.medium,
             "low": Severity.low, None: Severity.unknown}


@dataclass
class LanguageRun:
    """Result of the static stage for one language; kept in LanguageAnalysis.meta['secaudit']."""

    language: str                      # python | javascript | typescript
    work_dir: Path
    merged: list[MergedFinding] = field(default_factory=list)
    tools: dict[str, dict] = field(default_factory=dict)
    context: dict = field(default_factory=dict)
    loc: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def sast_dir(self) -> Path:
        return self.work_dir / "sast"

    @property
    def context_dir(self) -> Path:
        return self.work_dir / "context"

    def meta(self) -> dict:
        return {"language": self.language, "work_dir": str(self.work_dir), "tools": self.tools,
                "context": self.context, "loc": self.loc, "errors": self.errors,
                "merged_findings": len(self.merged)}


def tools_for(language: str, configured: dict | None = None) -> list[str]:
    """Tool list for a language: SECAUDIT_SAST_TOOLS env (comma list) > settings.yaml `sast.tools` > default."""
    env = os.environ.get("SECAUDIT_SAST_TOOLS", "").strip()
    if env:                                   # "none" disables SAST (context and LLM still run)
        return [] if env.lower() == "none" else [t.strip() for t in env.split(",") if t.strip()]
    family = FAMILY.get(language, language)
    lst = (configured or {}).get(family) or DEFAULT_TOOLS.get(family, [])
    return [str(t) for t in lst]


def detect_family_language(root: Path, family: str) -> str | None:
    """'python', 'javascript' or 'typescript' when the family is present in product code, else None."""
    cfg = load_sast_config()
    excludes = compile_excludes(cfg.path_excludes)
    exts = {lang: cfg.source_extensions.get(lang, []) for lang in ("python", "javascript", "typescript")}
    counts = {lang: 0 for lang in exts}
    skip = set(cfg.exclude_dirs) | {".git"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for name in filenames:
            rel = Path(dirpath, name).relative_to(root).as_posix()
            for lang, e in exts.items():
                if in_scope(rel, e, excludes):
                    counts[lang] += 1
                    break
    if family == "python":
        return "python" if counts["python"] else None
    js, ts = counts["javascript"], counts["typescript"]
    if not js and not ts:
        return None
    return "typescript" if ts > js else "javascript"


def count_loc(root: Path, language: str) -> int:
    cfg = load_sast_config()
    excludes = compile_excludes(cfg.path_excludes)
    exts = cfg.family_extensions(language)
    skip = set(cfg.exclude_dirs) | {".git"}
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for name in filenames:
            p = Path(dirpath, name)
            if in_scope(p.relative_to(root).as_posix(), exts, excludes):
                try:
                    total += sum(1 for _ in p.open("rb"))
                except OSError:
                    pass
    return total


def analyze_language(root: Path, language: str, work_dir: Path | None = None,
                     tools: list[str] | None = None) -> LanguageRun:
    """SAST + context for `language` in `root`. Outputs (SARIF, merged.jsonl, index.json...) go to work_dir."""
    from app.context.build import build_snapshot_context

    if work_dir is None:
        work_dir = Path(tempfile.mkdtemp(prefix=f"secaudit-{language}-"))
    run = LanguageRun(language=language, work_dir=work_dir)
    cfg = load_sast_config()
    toolmod.set_overrides(cfg.tool_paths)
    tools = tools if tools is not None else tools_for(language)
    run.loc = count_loc(root, language)

    if tools:
        try:
            results = run_tools_isolated(root, language, run.sast_dir, tools, cfg, item_id=root.name, side="adhoc")
            for tool, r in results.items():
                run.tools[tool] = {"ok": r.ok, "seconds": round(r.seconds, 1), "error": (r.error or "")[:300] or None}
            for f in io.read_jsonl(run.sast_dir / "findings.jsonl"):
                if f["tool"] in run.tools:
                    run.tools[f["tool"]]["findings"] = run.tools[f["tool"]].get("findings", 0) + 1
            merged = [MergedFinding.model_validate(r) for r in io.read_jsonl(run.sast_dir / "merged.jsonl")]
            run.merged = rank_sast([m for m in merged if in_product_code(m.file)])
        except Exception as exc:  # noqa: BLE001 - static stage must not kill the scan
            logger.exception("SAST failed for %s", language)
            run.errors.append(f"sast: {exc}")
    try:
        run.context = build_snapshot_context(root, language, run.context_dir)
    except Exception as exc:  # noqa: BLE001
        logger.exception("context build failed for %s", language)
        run.errors.append(f"context: {exc}")
    return run


def merged_to_finding(m: MergedFinding, language: str) -> Finding:
    """Analyzer Finding for a merged SAST cluster; cluster details are kept in `extra`."""
    cwe = m.cwe[0] if m.cwe else None
    first = (m.messages[0] if m.messages else "").strip()
    title = CWE_TITLES_RU.get(cwe or "", "") or first.split("\n")[0][:120] or (m.rule_ids[0] if m.rule_ids else "SAST")
    if cwe and title == CWE_TITLES_RU.get(cwe):
        title = f"{title} ({cwe})"
    return Finding(
        id=f"sast-{m.id}",
        title=title,
        description="\n".join(dict.fromkeys(x.strip() for x in m.messages if x.strip()))[:2000],
        severity=_SEVERITY.get(m.severity, Severity.unknown),
        cwe=cwe,
        file=m.file,
        line=m.start_line,
        rule_id=", ".join(m.rule_ids[:4]) or None,
        source="+".join(m.tools),
        language=FAMILY.get(language, language),
        remediation=REMEDIATION_RU.get(cwe or "", "Проверьте, может ли атакующий повлиять на данные в этой точке, "
                                                   "и устраните опасный паттерн согласно правилу анализатора."),
        extra={"cluster_id": m.id, "tools": m.tools, "rule_ids": m.rule_ids, "cwes": m.cwe,
               "end_line": m.end_line, "messages": m.messages[:5],
               "dataflow": [s.model_dump() for s in m.dataflow] if m.dataflow else None},
    )
