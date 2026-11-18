"""Rendering helpers: severity mapping, donut geometry, doc content."""

from __future__ import annotations

from worker.rendering import severity_counts, svg_donut


def test_severity_counts_maps_unknown_to_info(scan_result):
    counts = severity_counts(scan_result)
    assert counts == {"critical": 1, "info": 1}


def test_severity_counts_empty_summary(scan_result):
    scan_result.summary = {}
    assert severity_counts(scan_result) == {}


def test_svg_donut_segments_and_center(scan_result):
    counts = severity_counts(scan_result)
    svg = svg_donut(counts, {"critical": "#E86A6A", "info": "#8A5A73"})
    assert svg.count("<circle") == 2  # one segment per severity
    assert "#E86A6A" in svg
    assert ">2</text>" in svg  # total in the center


def test_svg_donut_empty_when_no_findings():
    assert svg_donut({}, {}) == ""
    assert svg_donut({"critical": 0}, {"critical": "#000"}) == ""


def test_render_report_structure(cfg, scan_result):
    html = render(scan_result, cfg, kind="report")
    assert "<!DOCTYPE html>" in html
    assert 'lang="ru"' in html
    assert "demo-app" in html
    assert "Отчёт аудита безопасности" in html
    assert "Слабое хеширование" in html
    assert "ИИ-анализ: skipped" in html
    # self-contained: no external resource references (sandboxed iframe)
    assert "http://" not in html and "https://" not in html
    assert "<script" not in html


def test_render_doc_structure(cfg, scan_result):
    html = render(scan_result, cfg, kind="doc")
    assert "Паспорт исследования" in html
    assert "Кодовая инвентаризация" in html
    assert "Протокол выявленных уязвимостей" in html
    assert "Выводы" in html
    assert "requirements.txt" in html
    assert "не выявлено" not in html  # there are findings, conclusions say so


def test_render_doc_without_findings(cfg, scan_result):
    scan_result.findings = []
    scan_result.summary = {"by_severity": {}}
    html = render(scan_result, cfg, kind="doc")
    assert "протокол не формируется" in html
    assert "уязвимостей не выявлено" in html


def render(result, cfg, kind: str) -> str:
    from worker.rendering import render_doc, render_report

    return render_report(result, cfg) if kind == "report" else render_doc(result, cfg)


def test_render_report_with_secaudit_analysis(cfg, scan_result):
    """Ranked findings show the LLM verdict, data flow and code; dismissed ones get their own table."""
    sqli, weak = scan_result.findings
    sqli.extra.update(rank=1, tools=["bandit", "semgrep"], verdict="true_positive",
                      triage={"verdict": "true_positive", "confidence": 0.9, "source": "request.args['id']",
                              "sink": "cursor.execute", "sanitizers": [], "preconditions": "network access",
                              "explanation": "Идентификатор подставляется в SQL без параметров."},
                      snippet={"start": 40, "lines": ["def get(id):", "    q = 'SELECT ' + id", "    run(q)"],
                               "highlight": [41, 41]})
    weak.extra.update(dismissed=True, tools=["bandit"],
                      triage={"verdict": "false_positive", "confidence": 0.8, "explanation": "MD5 для кеш-ключа."})
    scan_result.meta.update(ranking="S+T", llm={"enabled": True, "model": "m", "modes": ["triage"]},
                            attack_surface={"context": {"files": 3, "functions": 9, "entrypoints": 2, "sinks": 4},
                                            "entry_points": {"route": 2}, "sinks_by_cwe": {"CWE-89": 1},
                                            "tools": {"bandit": {"ok": True, "findings": 2, "seconds": 1.2},
                                                      "codeql": {"ok": False}}})
    html = render(scan_result, cfg, kind="report")
    assert "Поверхность атаки и методика" in html and "CodeQL" in html and "не выполнен" in html
    assert "подтверждено ИИ · 0.90" in html
    assert "request.args[&#39;id&#39;] → cursor.execute" in html
    assert 'class="hl"' in html and "SELECT" in html
    assert "Отклонено ИИ-триажем (1)" in html and "MD5 для кеш-ключа." in html
    assert "SAST + ИИ-триаж" in html
    assert "https://" not in html and "<script" not in html
    doc = render(scan_result, cfg, kind="doc")
    assert "Методика и средства анализа" in doc and "Поверхность атаки" in doc
    assert "(1 шт.)" in doc
