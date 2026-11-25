# Evaluation on real vulnerabilities

This page describes **how** llmflow is evaluated against known prompt-to-anything injection vulnerabilities and against published tools. Results are added once the runs finish.

> **Status:** results for both configurations are below: default `sdk`, and `fw` with framework sources. Held-out set and precision study: not run yet.

## Why an external benchmark

Synthetic apps written by us only show that the tool finds what we planted; they say nothing about whether those apps look like real code. They remain as regression tests (`tests/llmflow/`), not as evidence.

The evaluation uses an **independently curated ground truth**: the 35 real vulnerabilities from **TaintP2X** (He et al., ICSE 2026, [paper](https://xinyi-hou.github.io/files/icse26taintp2x.pdf), [artifact](https://github.com/security-pride/TaintP2X)). The TaintP2X authors built it from three sources:
- the vulnerabilities disclosed by LLMSmith (CCS '24) and AgentFuzz (USENIX Security '25);
- a search of NVD, the GitHub Advisory Database and huntr by two authors independently.

Every entry is a CVE or a public huntr report. The same paper publishes per-entry results for three tools, so llmflow can be compared on the same cases:
- **LLMSmith:** static analysis plus prompt-based testing;
- **AgentFuzz:** directed greybox fuzzing;
- **TaintP2X:** Pysa taint analysis plus LLM-assisted source identification and path validation.

## The benchmark

`config/llmflow/bench/taintp2x35.yaml` holds one entry per vulnerability:

| Field | Content | Where it comes from |
|---|---|---|
| `cve`, `class` | CVE id, vulnerability class (code / SQL injection, file read/write, SSRF) | TaintP2X Table 2 |
| `repo`, `ref` | repository and vulnerable version (tag or commit) | Table 2's version when that tag exists, otherwise the nearest tag inside the advisory's vulnerable range. OpenManus "2025.3.13" is the last commit of that day; devika is the commit named in its advisory |
| `path`, `exclude` | the package to scan in monorepos | the vulnerable code's location; e.g. `libs/experimental` for LangChain Experimental, LlamaIndex integrations excluded |
| `expect.file`, `expect.func` | where the vulnerable flow lives | the GitHub advisory text and its fix commit / huntr report |
| `scope` | `app` (the project calls an LLM SDK itself) or `framework` (the bug is inside LangChain / LlamaIndex / litellm) | our classification |
| `reported` | ✔ / ✘ / – for LLMSmith, AgentFuzz, TaintP2X | TaintP2X Table 2, verbatim |

A unit test checks that the transcription reproduces the published totals: LLMSmith 17, AgentFuzz 7, TaintP2X 27 out of 35.

The 35 entries split as follows:

| | Code injection | SQL injection | File read/write | SSRF | Total |
|---|---|---|---|---|---|
| **app** (Vanna, PandasAI, MetaGPT, OpenManus, AutoGPT, SuperAGI, devika, quivr) | 7 | 3 | 4 | 1 | **15** |
| **framework** (LangChain, LlamaIndex, litellm) | 15 | 4 | 0 | 1 | **20** |

## Procedure

```powershell
python -m app llmflow bench fetch                 # shallow clone every (repo, ref) → data/llmflow/bench/repos/
python -m app llmflow bench check                 # every expect.file exists in its checkout
python -m app llmflow bench run --md sdk.md       # configuration "sdk"
python -m app llmflow bench run --frameworks --md fw.md   # configuration "fw"
```

1. **Fetch.** Each repository is shallow-cloned at its ref (20 checkouts for 35 entries).
2. **Check.** `bench check` fails if an entry's expected file doesn't exist under its scan target. This catches wrong refs and paths in the manifest before any result is computed.
3. **Scan.** Each checkout is scanned once with default options and nothing tuned per repository. Entries sharing a checkout reuse the scan. Outputs go to `data/llmflow/bench/out/<config>/<checkout>/`.
4. **Match.** An entry counts as **detected** when one reported flow meets all of these:
   - one of its hops is in a file matching `expect.file` and a function matching `expect.func`;
   - its sink class fits the vulnerability class:

     | Class | Accepted sink classes |
     |---|---|
     | code_injection | `code_eval`, `shell`, `deserialize` |
     | sql_injection | `sql` |
     | file_rw | `file_write`, `text` |
     | ssrf | `http` |

   The rank and priority of the best matching flow are recorded.
5. **Report.** `results.json` and the Markdown table give a per-entry comparison with the three published columns, plus a recall summary.

### Configurations

| Config | LLM-output sources | Purpose |
|---|---|---|
| `sdk` | SDK calls only: openai, anthropic, ollama (`config/llmflow/sdks/`) | the default tool |
| `fw` | plus LangChain / LlamaIndex / litellm abstractions (`config/llmflow/frameworks/`, opt-in `--frameworks`) | framework-internal bugs; closer to TaintP2X's 97 predefined sources |

### Metrics

- **Recall** = detected / entries, computed separately for `app`, `framework` and all. The published tools get the same breakdown from their Table 2 columns.
- **Ranking quality.** Among detected entries, how many land at rank ≤ 1 / 3 / 10, ranked by S·E·R versus by sink severity S alone (`rank_by_S`). The published tools report detection only, not a ranking, so this has no counterpart in the comparison.
- **Cost.** Wall-clock scan time per checkout.

## What the comparison can and cannot say

- **Published numbers, not re-runs.** All three columns come from TaintP2X's Table 2. None of the tools was run here: TaintP2X needs Pyre/Pysa plus an LLM API (DeepSeek-V3 in the paper), and AgentFuzz needs the target apps running.
  - **Unclear how the baseline columns were obtained.** The paper says it "selected" LLMSmith and AgentFuzz as baselines, without saying whether the TaintP2X authors re-ran them or took their published disclosures. A dash means the tool cannot analyse that case: unsupported framework, language or vulnerability type.
  - **The matching criterion isn't defined** beyond "detected". The comparison is per entry, but not under an identical protocol.
- **Selection bias towards the baselines.** 17 of the 35 entries are vulnerabilities originally *discovered and disclosed* by LLMSmith and AgentFuzz, and that is how they entered the ground truth.
  - LLMSmith's column (17 ✔) is mostly its own disclosures: the LangChain, LlamaIndex and PandasAI CVEs.
  - AgentFuzz's (7 ✔) is mostly its own Vanna and quivr findings.

  Their recall here is therefore not an independent measurement. TaintP2X's and llmflow's are less affected, although TaintP2X's authors also built the set.
- **Static against hybrid.** llmflow makes no LLM calls. TaintP2X's reported column is its full pipeline, LLM stages included. Its paper only reports the static core (M2) separately on the 4,772-repo corpus, not on these 35 entries.
- **Localization varies.** Most entries name a concrete function: `LLMMathChain`, `PALChain`, `RunCode`, `get_plotly_figure`, and so on. A few advisories are vague and use file-level expectations (`func: '.'`):
  - devika ×3 (CVE-2024-5927 was later rejected by its CNA);
  - SuperAGI (a huntr report);
  - quivr;
  - LangChain Experimental's REPL (CVE-2024-38459);
  - litellm (CVE-2024-6825).

  The litellm entry is a config value reaching `importlib`, not model output.
- **Manifest corrections after seeing results.** One expectation was tightened after a run.
  - **What happened:** P26 (CVE-2024-23751, LlamaIndex Text-to-SQL) first matched a *different* LLM → SQL path, `StructDatapointExtractor` → `insert_into_table`, because the function regex `SQL` also matched `SQLDatabase.insert_into_table`.
  - **The fix:** the entry now pins the vulnerable call (`expect.sink: run_sql`) and the NL-to-SQL classes.
  - **Effect:** this lowered llmflow's own score. Every hit is still listed with its full path in `results.json` and was checked by hand.
- **Versions.** Where Table 2 gives a range rather than a version ("<0.0.236"), the nearest tag inside the range is used. Its code may differ from the exact version TaintP2X analysed.
- **Tuning on the test set.** Several general changes were made while working with these repositories:
  - framework sources (`--frameworks`);
  - class-qualified matching of generic method names (`PythonREPL.run`);
  - wrappers with generic names (`call`) followed through `self.call(...)` only. This was added after the first run missed PandasAI;
  - `numexpr.evaluate` as a code sink;
  - a fix to the Ollama receiver regex, which is anchored at the start by Semgrep.

  Each change is documented, covered by its own rule tests or end-to-end tests, and not specific to one CVE. Still, results on this benchmark are optimistic for that reason. **A held-out set is needed:**
  - CWE-1427 / GitHub Advisory / huntr cases disclosed after TaintP2X's collection;
  - the AgentFuzz agent applications not in this table.

  The held-out evaluation is planned and not yet run.
- **Precision is not measured here.** Every entry is a true vulnerability, so this benchmark measures recall only. Precision needs a sample of real projects with every reported flow labelled by hand: either TaintP2X's corpus (in their artifact's `dataset.7z`) or one rebuilt with the same criteria. That is also planned.

## Results: default configuration (`sdk`)

Run on 2026-11-25: Windows 11, Python 3.13, Semgrep 1.187, default options. Raw data is in `data/llmflow/bench/sdk/results.json` (local, gitignored); reproduce it with `python -m app llmflow bench run`.

### Recall

| Scope | LLMSmith | AgentFuzz | TaintP2X | **llmflow** |
|---|---|---|---|---|
| app (15) | 4 | 7 | 13 | **11** |
| framework (20) | 13 | 0 | 14 | **1** |
| all (35) | 17 | 7 | 27 | **12** |

The other three columns are TaintP2X's published Table 2.

- **App-level code (the projects llmflow targets).** 11 of 15, behind TaintP2X (13) and ahead of AgentFuzz (7) and LLMSmith (4).
  - **Found by llmflow, missed by TaintP2X:** Vanna CVE-2024-7764 (`generate_sql` → `run_sql(intermediate_sql)`).
  - **Found by TaintP2X, missed by llmflow:** MetaGPT, OpenManus and quivr. Each is explained under misses below.
- **Framework internals.** 1 of 20. This is expected for the default configuration: the model output there comes from LangChain's and LlamaIndex's own abstractions (`llm_chain.predict`, `llm_predictor.predict`), which the SDK catalog doesn't treat as sources.
  - **The one hit:** LangChain's `LLMMathChain` → `numexpr` (CVE-2023-39631). It's found because LangChain's own LLM classes call the provider SDKs, so the wrapper fixpoint climbs up to the chain.
  - **What closes the gap:** the `fw` configuration (in progress).

### Ranking

Ranks of the 12 detected vulnerabilities among all findings in their repository:

| | rank 1 | ≤ 3 | ≤ 10 |
|---|---|---|---|
| **S·E·R** (llmflow) | **8** | **9** | 12 |
| S only | 6 | 8 | 12 |

Every detected vulnerability is in the top 10 of its repository, and two-thirds are the top finding. S·E·R improves on ranking by sink severity alone at rank 1 (8 against 6). The gain comes from exposure: a web-reachable flow outranks the same sink reached only through a CLI or with unknown provenance. The sample is small, so treat this as a direction, not a measurement.

### Per entry

| id | CVE | project @ version | class | LLMSmith | AgentFuzz | TaintP2X | llmflow | rank · priority |
|---|---|---|---|:-:|:-:|:-:|:-:|---|
| P16 | CVE-2024-23750 | MetaGPT 0.6.3 | code | ✘ | – | ✔ | ✘ | |
| P17 | CVE-2025-2733 | OpenManus 2025-03-13 | code | ✘ | ✘ | ✔ | ✘ | |
| P18 | CVE-2023-39660 | PandasAI 0.8.0 | code | ✔ | – | ✔ | **✔** | #1 · 0.25 |
| P19 | CVE-2023-39661 | PandasAI 0.8.1 | code | ✔ | – | ✔ | **✔** | #1 · 0.25 |
| P20 | CVE-2024-5826 | Vanna 0.3.3 | code | ✔ | ✔ | ✔ | **✔** | #1 · 0.50 |
| P21 | CVE-2024-5565 | Vanna 0.3.1 | code | ✔ | ✔ | ✔ | **✔** | #1 · 0.50 |
| P22 | CVE-2024-1881 | AutoGPT 0.5.0 | code | ✘ | ✔ | ✘ | ✘ | |
| P27 | CVE-2024-5753 | Vanna 0.3.4 | sql | – | ✔ | ✔ | **✔**¹ | #4 · 0.23 |
| P28 | CVE-2024-5827 | Vanna 0.3.4 | sql | – | ✔ | ✔ | **✔**¹ | #4 · 0.23 |
| P29 | CVE-2024-7764 | Vanna 0.6.2 | sql | – | ✔ | ✘ | **✔** | #2 · 0.45 |
| P30 | huntr report | SuperAGI 0.0.14 | file | – | ✘ | ✔ | **✔** | #4 · 0.20 |
| P31 | CVE-2024-5927 | devika (commit cdfb782) | file | – | ✘ | ✔ | **✔** | #1 · 0.20 |
| P32 | CVE-2024-5821 | devika (commit cdfb782) | file | – | ✘ | ✔ | **✔**² | #1 · 0.20 |
| P33 | CVE-2024-6331 | devika (commit cdfb782) | file | – | ✘ | ✔ | **✔**² | #1 · 0.20 |
| P34 | CVE-2024-5885 | quivr 0.0.236 | ssrf | – | ✔ | ✔ | ✘ | |
| P08 | CVE-2023-39631 | LangChain 0.0.245 | code (framework) | ✘ | – | ✔ | **✔** | #1 · 0.25 |
| *other framework entries* | 19 entries | LangChain, LlamaIndex, litellm | | 13 ✔ | 0 ✔ | 13 ✔ | ✘ | |

¹ Vanna 0.3.4's two SQL CVEs differ in the database backend used for the exploit: `pg_read_file` on Postgres, `COPY … TO` on DuckDB. llmflow reports the shared root cause, LLM-generated SQL passed to `run_sql`. Through the `self.run_sql = run_sql_<backend>` aliases it surfaces one backend (MySQL), so both entries match the same finding.
² The three devika advisories share one finding: the coder agent writes files whose names the model chooses (`save_code_to_project` → `open(file_path, "w")`). CVE-2024-6331 is described as a local file *read*, so for that entry the match is about the root cause, not the exact exploit. TaintP2X counts all three as detected too.

A strict count, accepting only a finding that is the advisory's exact path, would drop P33 and count P27/P28 as one finding. That gives 9–10 of 15 for app-level code.

### Why the misses

| Entry | Cause | What would fix it |
|---|---|---|
| MetaGPT CVE-2024-23750 | The command reaches `RunCode.run_script` through message and context objects (`self.context…`), i.e. attributes across methods | a minimal field model (see [stitching.md](stitching.md)) |
| OpenManus CVE-2025-2733 | The model calls `PythonExecute`, a tool class registered in a `ToolCollection`; the inventory binds only `tools=` literals, functions and dispatch dicts | class-based tool binding (also the anthropic-quickstarts miss in [examples.md](examples.md)) |
| AutoGPT CVE-2024-1881 | Commands are registered with `@command` decorators and dispatched from parsed JSON. TaintP2X misses it too; only the fuzzer finds it | decorator-registered tools |
| quivr CVE-2024-5885 | No SDK call site: quivr uses LangChain. The crawled URL is supplied by the user, not chosen by the model | `fw` configuration for the LangChain part. Arguably not a model-output flow |
| 19 framework entries | Model output comes from framework abstractions | `fw` configuration (running) |

### Cost

30 checkouts (35 entries) took **15 minutes** in total on a laptop, with a median of 22 s per checkout. The largest was `langchain-community` 0.2.5: 1,174 files and 7,791 functions in 83 s. llmflow makes no LLM calls, so a run costs nothing beyond CPU and is deterministic.

## Results: framework configuration (`fw`)

Same checkouts and protocol, with `--frameworks`: LangChain, LlamaIndex and litellm abstractions count as LLM-output sources.

| Scope | LLMSmith | AgentFuzz | TaintP2X | llmflow `sdk` | **llmflow `fw`** |
|---|---|---|---|---|---|
| app (15) | 4 | 7 | 13 | 11 | **11** |
| framework (20) | 13 | 0 | 14 | 1 | **7** |
| all (35) | 17 | 7 | 27 | 12 | **18** |

- **New hits:** LangChain `PALChain` → `PythonREPL.run` → `exec` in five versions (CVE-2023-36095, -36258, -36188, -38896, -38860), and LangChain Experimental `PALChain` (CVE-2024-27444).
  - Each path is the advisory's: `llm_chain.predict(...)` → `repl.run(code)`, linked by the class-qualified match on the generic `run`.
  - `numexpr` in `LLMMathChain` (CVE-2023-39631) stays detected.
- **App-level code is unchanged.** Its misses need attribute tracking or class-based tools, not more sources.
- **Ranking is mixed here.** Among the 18 detected, S·E·R puts 9 at rank 1 and sink severity alone puts 12 at rank 1.
  - **Why:** the framework flows all have unknown prompt provenance (E = 0.5). Other flows in the same framework with a found untrusted source outrank them.
  - **Takeaway:** on app code S·E·R ranks better (7 vs 5 at rank 1), and on framework internals it ranks worse. The exposure model assumes application entry points, which framework code doesn't have.
- **Cost:** framework sources make the framework repositories 1.5–3× slower, up to about 3 minutes (litellm, `langchain-community`). App repositories are unchanged.

**Framework misses**

| Entries | Cause |
|---|---|
| CVE-2023-39659, CVE-2024-38459 (`PythonAstREPLTool`, agent toolkits) | the model reaches the REPL through **agent tools defined as classes**: the class-based-tools gap |
| LlamaIndex CVE-2024-3271, -3098, CVE-2023-39662 (`PandasQueryEngine` / `safe_eval`) | flows exist in these repositories but not on the advisory's path; under investigation |
| CVE-2023-29374 (`LLMMathChain` 0.0.131), CVE-2023-44467 (Experimental `PALChain` 0.0.305) | **unexplained so far.** Source and sink are each found, and the class-qualified sink pattern matches the call in isolation, but the parameter-to-sink fragment that should link them is not produced. A stitching bug to fix |
| LangChain `SQLDatabaseChain` (CVE-2025-27135), `GraphCypherQAChain` (CVE-2024-8309), APIChain SSRF (CVE-2023-32786); LlamaIndex JSONalyze (CVE-2024-12911), Text-to-SQL (CVE-2024-23751) | the model output reaches the database or HTTP call through framework objects (`self.database.run`, `self.requests_wrapper.get`): attribute-held objects that name-based stitching doesn't follow |
| litellm CVE-2024-6825 | a config value reaching `importlib`, not model output. Missed by every tool |

**Corrections after this run** (all lower llmflow's score): three expectations matched a flow that was not the advisory's.
- **CVE-2023-29374** (`LLMMathChain`) matched a `PALChain` flow, because the regex also accepted any `PythonREPL` hop.
- **The `PALChain` entries** got the same tightening as a precaution.
- **CVE-2024-38459** (agent toolkits) matched a `PALChain` flow through a file-level regex.

Each now requires the path to pass through the advisory's class: `LLMMathChain`, `PALChain`, or the agent toolkit / REPL tool.
