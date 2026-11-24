# Benchmark comparison

Pooled per-corpus metrics (n-weighted over splits) from `results/metrics.json`; per-item numbers and confidence intervals live in each corpus's `results/report.md`.

## pilot

*splits: dev · data: `data\bench\pilot`*

| config | n | R@1 | R@10 | MRR | PairAcc@10 | findings/KLOC |
|---|---|---|---|---|---|---|
| S | 4 | 100% | 100% | 1.00 | 25% | 6476.2 |
| S-bandit | 1 | 100% | 100% | 1.00 | 100% | 333.3 |
| S-devskim | 4 | 100% | 100% | 1.00 | 100% | 190.5 |
| S-graudit | 4 | 75% | 75% | 0.75 | 0% | 6190.5 |
| S-joern | 1 | 100% | 100% | 1.00 | 100% | 142.9 |
| S-opengrep | 4 | 100% | 100% | 1.00 | 100% | 190.5 |
| S-security-code-scan | 1 | 100% | 100% | 1.00 | 100% | 142.9 |
| S-semgrep | 4 | 100% | 100% | 1.00 | 100% | 190.5 |
| S-spotbugs | 1 | 100% | 100% | 1.00 | 100% | 142.9 |

*scan coverage:* bandit 2/2 ok · devskim 8/8 ok · graudit 8/8 ok · joern 2/2 ok · opengrep 8/8 ok · security-code-scan 2/2 ok · semgrep 8/8 ok · spotbugs 2/2 ok

## published-pilot

*splits: dev, test · data: `data\bench\published-pilot`*

| config | n | R@1 | R@10 | MRR | PairAcc@10 | findings/KLOC |
|---|---|---|---|---|---|---|
| S | 4 | 0% | 0% | 0.01 | 0% | 15.9 |
| S-bandit | 2 | 0% | 0% | 0.00 | 0% | 1.7 |
| S-devskim | 4 | 0% | 0% | 0.00 | 0% | 9.1 |
| S-graudit | 4 | 0% | 0% | 0.02 | 0% | 4.6 |
| S-opengrep | 4 | 0% | 0% | 0.00 | 0% | 0.0 |
| S-semgrep | 4 | 0% | 0% | 0.00 | 0% | 1.1 |

*scan coverage:* bandit 4/4 ok · devskim 8/8 ok · graudit 8/8 ok · opengrep 8/8 ok · semgrep 8/8 ok

## jc-pilot

*splits: dev · data: `data\bench\jc-pilot`*

| config | n | R@1 | R@10 | MRR | PairAcc@10 | findings/KLOC |
|---|---|---|---|---|---|---|
| S | 10 | 10% | 30% | 0.14 | 0% | 25.2 |
| S-devskim | 10 | 0% | 20% | 0.06 | 0% | 3.0 |
| S-graudit | 10 | 0% | 30% | 0.12 | 0% | 22.4 |
| S-joern | 5 | 0% | 0% | 0.00 | 0% | 0.0 |
| S-opengrep | 10 | 0% | 0% | 0.00 | 0% | 0.0 |
| S-security-code-scan | 1 | 0% | 0% | 0.00 | 0% | 0.0 |

*scan coverage:* devskim 20/20 ok · graudit 20/20 ok · joern 10/10 ok · opengrep 20/20 ok · security-code-scan 2/10 ok (4 error, 4 prepare_error) · spotbugs 0/10 ok (10 prepare_error)

## owasp-java

*splits: dev · data: `data\bench\owasp-java`*

| config | n | R@1 | R@10 | MRR | PairAcc@10 | findings/KLOC |
|---|---|---|---|---|---|---|
| S | 11 | 9% | 9% | 0.09 | 0% | 143.0 |
| S-graudit | 11 | 0% | 0% | 0.00 | 0% | 142.9 |
| S-opengrep | 11 | 9% | 9% | 0.09 | 0% | 0.1 |

*scan coverage:* devskim 0/11 ok (11 timeout) · graudit 11/11 ok · opengrep 11/11 ok

## owasp-python

*splits: dev · data: `data\bench\owasp-python`*

| config | n | R@1 | R@10 | MRR | PairAcc@10 | findings/KLOC |
|---|---|---|---|---|---|---|
| S | 14 | 0% | 7% | 0.03 | 0% | 59.3 |
| S-bandit | 14 | 7% | 14% | 0.08 | 0% | 8.0 |
| S-devskim | 14 | 0% | 7% | 0.04 | 0% | 25.8 |
| S-graudit | 14 | 0% | 0% | 0.00 | 0% | 25.5 |
| S-opengrep | 14 | 7% | 7% | 0.07 | 0% | 0.3 |
| S-semgrep | 14 | 0% | 14% | 0.03 | 0% | 2.8 |

*scan coverage:* bandit 14/14 ok · devskim 14/14 ok · graudit 14/14 ok · opengrep 14/14 ok · semgrep 14/14 ok

## realvuln

*splits: dev · data: `data\bench\realvuln`*

| config | n | R@1 | R@10 | MRR | PairAcc@10 | findings/KLOC |
|---|---|---|---|---|---|---|
| S | 20 | 25% | 75% | 0.40 | 0% | 8.8 |
| S-bandit | 8 | 50% | 88% | 0.67 | 0% | 10.1 |
| S-devskim | 20 | 5% | 30% | 0.12 | 0% | 4.2 |
| S-graudit | 20 | 20% | 75% | 0.39 | 0% | 4.6 |
| S-joern | 4 | 0% | 0% | 0.00 | 0% | 0.0 |
| S-opengrep | 20 | 0% | 5% | 0.03 | 0% | 0.0 |
| S-semgrep | 16 | 44% | 69% | 0.55 | 0% | 0.3 |

*scan coverage:* bandit 8/8 ok · devskim 20/20 ok · graudit 20/20 ok · joern 4/4 ok · opengrep 20/20 ok · semgrep 16/16 ok · spotbugs 0/4 ok (4 prepare_error)

## Notes

- PairAcc applies only to corpora with a fixed side (OWASP and RealVuln are recall-only).
- OWASP corpora scan the shared tree once per (repo, commit); the coverage line counts one observation per item, so scans are reused across category items.
- seclens is pending dataset access (gated on HuggingFace); no numbers yet.

