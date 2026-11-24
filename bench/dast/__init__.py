"""DAST benchmark stage: run live scanners (ZAP, Wapiti, Nuclei, OFFAT, Nikto) against
the same corpora the SAST benchmark uses (OWASP BenchmarkJava/Python, RealVuln).

Layout per corpus data dir (SECBENCH_DATA):

    dast/targets.json                       live target registry written by `dast up`
    dast/<target_id>/<tool>.json            raw tool report (copied out of containers)
    dast/<target_id>/<tool>.status.json     per-tool run manifest (DastToolResult)
    dast/<target_id>/<tool>.findings.jsonl  normalized DastFinding rows
    results/dast_metrics.json               per-tool TP/FP/FN/precision/recall (dast eval)
    results/dast_report.md                  human-readable report (dast eval)

OWASP corpora are scored per HTTP test case against the expectedresults CSV
(true/false + CWE per test); RealVuln is scored per item by CWE overlap.
"""

from __future__ import annotations
