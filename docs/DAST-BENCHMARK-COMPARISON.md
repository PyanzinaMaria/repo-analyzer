# DAST benchmark comparison

Per-corpus metrics from `results/dast_metrics.json` (`python -m bench dast eval <kind>`); per-tool raw runs live under each corpus's `dast/` directory.

## owasp-java

*mode: owasp · generated: 2026-11-25T10:15:52+00:00 · лимит: 1800 c на тул/цель*

| tool | TP | FP | FN | Precision | Recall | F1 | TP-rate | FP-rate | cwe-agree | non-test | время |
|---|---|---|---|---|---|---|---|---|---|---|---|
| nikto | 0 | 6 | 1415 | 0% | 0% | – | 0% | 0% | – | 6 | 58с |
| nuclei | 0 | 6 | 1415 | 0% | 0% | – | 0% | 0% | – | 6 | 2м05с |
| offat | 0 | 0 | 1415 | – | 0% | – | 0% | 0% | – | 0 | – |
| wapiti | 0 | 0 | 1415 | – | 0% | – | 0% | 0% | – | 0 | – |
| zap | 24 | 82 | 1391 | 23% | 2% | 3% | 2% | 6% | 0% | 71 | 43м08с |

*coverage:* nikto: 1 ok · nuclei: 1 ok · offat: 1 failed · wapiti: 1 failed · zap: 1 ok

## owasp-python

*mode: owasp · generated: 2026-11-25T10:15:51+00:00 · лимит: 1800 c на тул/цель*

| tool | TP | FP | FN | Precision | Recall | F1 | TP-rate | FP-rate | cwe-agree | non-test | время |
|---|---|---|---|---|---|---|---|---|---|---|---|
| nikto | 0 | 2 | 452 | 0% | 0% | – | 0% | 0% | – | 2 | 30с |
| nuclei | 0 | 0 | 452 | – | 0% | – | 0% | 0% | – | 0 | 6м46с |
| offat | 452 | 778 | 0 | 37% | 100% | 54% | 100% | 100% | 0% | 0 | 9м55с |
| wapiti | 0 | 0 | 452 | – | 0% | – | 0% | 0% | – | 0 | – |
| zap | 64 | 119 | 388 | 35% | 14% | 20% | 14% | 15% | 54% | 74 | 43м10с |

*coverage:* nikto: 1 ok · nuclei: 1 ok · offat: 1 ok · wapiti: 1 failed · zap: 1 ok

## realvuln

*mode: items · generated: 2026-11-25T10:15:50+00:00 · лимит: 1800 c на тул/цель*

| tool | items | hit | Recall(items) | TP(findings) | FP | Precision | время |
|---|---|---|---|---|---|---|---|
| nikto | 1 | 0 | 0% | 0 | 9 | 0% | 14с |
| nuclei | 1 | 0 | 0% | 0 | 13 | 0% | 1м42с |
| offat | 1 | 0 | 0% | 0 | 0 | – | – |
| wapiti | 1 | 0 | 0% | 0 | 0 | – | 10с |
| zap | 1 | 1 | 100% | 2 | 46 | 4% | 5м50с |

*coverage:* nikto: 1 ok · nuclei: 1 ok · offat: 1 skipped · wapiti: 1 ok · zap: 1 ok

## Notes

- OWASP corpora score per test case: URL -> BenchmarkTestNNNNN -> expectedresults CSV (true/false + CWE); non-test findings count as FP and are listed separately.
- RealVuln has no URL-level ground truth, so it is scored per app by CWE overlap (cwe_overlap families); precision there is a proxy, not a true FP count.
- OFFAT requires an OpenAPI spec: generated from pinned routes for OWASP, probed live for RealVuln (apps without a spec are skipped as no_openapi).
- Each tool gets a fixed time budget per target (config/dast.yaml scan_timeout_s); ZAP/Nikto caps limit coverage on the 2740-endpoint BenchmarkJava.

