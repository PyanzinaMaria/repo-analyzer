# The llmflow catalog

Everything llmflow knows about SDKs, sinks, untrusted inputs, gates and models lives in YAML under `config/llmflow/`. The Semgrep rules are **generated** from it (`app/llmflow/rulegen.py`), and each entry is covered by `semgrep --test` snippets in `config/llmflow/tests/`.

```
config/llmflow/
├── sdks/
│   ├── openai.yaml      # v1 client API + legacy openai.ChatCompletion
│   ├── anthropic.yaml
│   └── ollama.yaml
├── sinks.yaml           # dangerous sink classes → S
├── sources.yaml         # untrusted input kinds → base E
├── gates.yaml           # checks that limit an attacker → E factor
├── kb.yaml              # model knowledge base → R
├── hygiene.yaml         # raw Semgrep hygiene rules
└── tests/               # semgrep --test snippets (one file per rule family)
```

## SDK entries (`sdks/*.yaml`)

```yaml
sdk: openai
provider: openai
imports: [openai]
calls:
  - id: openai.chat                       # stable id → rule llmflow.callsite.openai.chat
    callee: $C.chat.completions.create    # Semgrep expression, no argument list; $C = any receiver
    channel: chat                         # chat | completion | responses (tool calls get tool_call)
    model_arg: model                      # keyword holding the model name (model_pos: positional index)
    prompt_args: [messages]               # keywords that carry the prompt (prompt_pos: positional indexes)
    tools_arg: tools                      # keyword holding tool declarations
```

The generator builds several things from one entry:

| Generated | Pattern | Used for |
|---|---|---|
| call site | `$C.chat.completions.create(...)` | inventory |
| LLM-output source | same, with `exact: true` | `o2s` taint rules (the result is model output; its arguments are not) |
| prompt sink | `$C.chat.completions.create(..., messages=$X, ...)` | `i2p` and `par` taint rules |

Fields for SDKs whose methods have generic names:

| Field | Example | Effect |
|---|---|---|
| `inside_import` | `[ollama]` | the file must `import ollama` / `from ollama import …` |
| `receiver_regex` | `'(?i)ollama'` | …or the receiver is named like the SDK (`self.ollama_client`, for `ollama = __import__("ollama")`) |
| `require_kwargs` | `[model, messages]` | the call must pass these keywords (`$C.chat(model=…, messages=…)`) |
| `exclude` | `[$C.chat.completions.create]` | callees this entry must not match (`$C.completions.create` would also match `client.chat.completions.create`) |

**SDK aliases are found automatically.** If the code binds an SDK method to a name, such as `completion = client.chat.completions.create`, the inventory adds a call entry for `completion(...)` (this is how shell_gpt calls the model).

### Adding an SDK

1. Create `config/llmflow/sdks/<name>.yaml` with one `calls` entry per API.
2. Add `config/llmflow/tests/callsite_<name>.py`, annotating each call:

   ```python
   # ruleid: llmflow.callsite.<name>.chat
   client.chat(model="x", messages=msgs)
   # ok: llmflow.callsite.<name>.chat
   room.chat(text)
   ```
3. Add a direct output → sink case to `tests/flows.py` if the SDK returns output in a new shape.
4. Run `python -m app llmflow test-rules`.

## Sinks (`sinks.yaml`)

Every pattern must bind **`$X`** to the dangerous argument; the loader rejects patterns that don't.

```yaml
classes:
  shell:
    S: 1.0
    cwe: CWE-78
    title: OS command execution
    patterns:
      - pattern: subprocess.$FN($X, ...)
        regex: {$FN: '^(run|call|check_call|check_output|Popen|getoutput|getstatusoutput)$'}
      - pattern: os.system($X)
```

| Class | S | CWE | Examples |
|---|---|---|---|
| `shell` | 1.0 | CWE-78 | `subprocess.*`, `os.system`, `os.popen`, `asyncio.create_subprocess_*`, `pexpect` |
| `code_eval` | 1.0 | CWE-94 | `eval`, `exec`, `compile`, `runpy.run_path` |
| `sql` | 0.9 | CWE-89 | `*.execute*`, `sqlalchemy.text`, `pandas.read_sql*`, `duckdb.sql` |
| `deserialize` | 0.9 | CWE-502 | `pickle.loads`, `yaml.load` (not SafeLoader), `dill.loads` |
| `file_write` | 0.8 | CWE-22 | the model chooses the **path**: `open($X)`, `Path($X)`, `os.remove`, `shutil.*` |
| `http` | 0.7 | CWE-918 | `requests.*`, `httpx.*`, `urlopen` |
| `html` | 0.5 | CWE-79 | `Markup`, `render_template_string`, `markdown.markdown`, `st.markdown(unsafe_allow_html=True)` |
| `text` | 0.1 | CWE-117 | `print`, logging, content written to a fixed file. **Off by default** (`--sinks text`) |

## Untrusted sources (`sources.yaml`)

| Kind | E | Examples |
|---|---|---|
| `web_request` | 1.0 | `flask.request.*`, `request.GET/POST`, `query_params`, `bottle.request` |
| `web_content` | 1.0 | `requests.get(...)`, `httpx.get(...)`, `urlopen`, `BeautifulSoup` |
| `retrieved_doc` | 1.0 | `similarity_search`, `get_relevant_documents`, `retrieve`, Chroma `query(query_texts=…)` |
| `ui_input` | 1.0 | `st.text_input`, `st.chat_input` |
| `email_or_file_upload` | 1.0 | `request.files[...]`, `email.message_from_*` |
| `local_file` | 0.5 | `open(...).read()`, `Path.read_text()` |
| `cli` | 0.5 | `input()`, `sys.argv`, `argparse`, `click/typer.prompt` |
| route parameter | 1.0 / 0.3 | parameters of route handlers (`app/context/entrypoints.py`); 0.3 when the decorators mention login/auth/admin |
| unknown | 0.5 | LLM output whose prompt provenance was not found |

## Gates (`gates.yaml`)

```yaml
factors: {deterministic: 0.05, confirmation: 0.3, weak: 0.6}
gates:
  - id: allowlist
    kind: deterministic
    applies_to: ['*']            # or a list of sink classes
    patterns:
      - |
        if $V not in $ALLOW:
          ...
    regex: {$ALLOW: '(?i)(allow|whitelist|permitted|safe|known|valid|supported)'}
```

A gate counts for a flow only if **all** of these hold:
- it sits in a function on the flow's path;
- it comes after the LLM call (when in the same function) and at or before the line where the path leaves that function;
- it applies to the flow's sink class;
- if it binds `$V`, it mentions an identifier of the tainted value.

| Gate | Kind | Factor | Applies to |
|---|---|---|---|
| `allowlist` | deterministic | 0.05 | all |
| `shlex-quote` | deterministic | 0.05 | shell |
| `html-escape` | deterministic | 0.05 | html |
| `sql-readonly` | deterministic | 0.05 | sql |
| `sql-parse-check` | deterministic | 0.05 | sql |
| `path-confine` | deterministic | 0.05 | file_write |
| `schema-validate` | deterministic | 0.05 | all |
| `human-confirm` | confirmation | 0.3 | all |
| `prefix-check` | weak | 0.6 | all |
| `regex-check` | weak | 0.6 | all |

## Model knowledge base (`kb.yaml`)

The KB has five entries: `gpt-4o`, `gpt-4o-mini`, `claude-sonnet`, `llama3`, `qwen2.5`. Each lists alias regexes, provider, features (tools, JSON mode, system prompt, vision) and status.

R is **0.5 everywhere** in this baseline. A per-channel slot exists (`R.channels.tool_call`), and every value is clamped to `[0.3, 0.9]`. Tags such as `llama3.1:8b` match their family, and the more specific alias wins (`gpt-4o-mini` over `gpt-4o`).

## Hygiene rules (`hygiene.yaml`)

These are raw Semgrep rules, reported separately and not ranked:

| Rule | CWE |
|---|---|
| `hardcoded-api-key` | CWE-798 |
| `client-no-timeout` | CWE-400 |
| `untrusted-in-system-role` | CWE-1427 |
| `response-logged` | CWE-532 |
| `tls-verify-disabled` | CWE-295 |
| `no-max-tokens` | CWE-770 |
| `tool-args-unvalidated` | CWE-20 |
| `user-controlled-model` | CWE-15 |
| `shell-true-in-llm-module` | CWE-78 |
| `plaintext-base-url` | CWE-319 |

## Rule tests

`python -m app llmflow test-rules` generates the rules, pairs each snippet file with the rule family its name starts with, and runs `semgrep --test` in a separate directory per pair. The separate directories avoid a race on Semgrep's settings file on Windows.

| Snippet | Rule family |
|---|---|
| `callsite_openai.py`, `callsite_anthropic.py`, `callsite_ollama.py` | `llmflow.callsite.*` |
| `flows.py` | `llmflow.o2s.*`, `llmflow.i2p.*`, `llmflow.par.*` |
| `gates.py` | `llmflow.gate.*` |
| `hygiene.py` | `llmflow.hygiene.*` |
