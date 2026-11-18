#!/usr/bin/env bash
# Re-record the CLI demo GIFs in docs/img/ from real runs (needs a built benchmark, SAST and LLM outputs).
# Casts are rendered to GIF by scripts/cast2gif.py (pyte + Pillow; `pip install -e .[docs]`).
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
PY="${PY:-$HOME/.venvs/repo-analyzer/bin/python}"
MODEL="${MODEL:-nvidia/nemotron-3-ultra-550b-a55b:free}"
ITEM="${ITEM:-js-CVE-2015-3295}"
CASTS="$REPO/docs/casts"
render() {  # cast -> gif
  "$PY" scripts/cast2gif.py "$CASTS/$1.cast" "docs/img/$1.gif" --title "$2"
}

# 1. SAST on a toy app (real run: semgrep, bandit, codeql)
"$PY" scripts/record_demo.py "$CASTS/demo_sast.cast" --height 24 --width 100 \
  --show "python -m bench sast run --path tests/fixtures/toy-py-flask --force" \
  -- bash scripts/sb sast run --path tests/fixtures/toy-py-flask --force
render demo_sast "secaudit · SAST"

# 2. LLM triage (answers come from the cache: same prompts, $0)
"$PY" scripts/record_demo.py "$CASTS/demo_triage.cast" --height 22 --width 100 \
  --show "python -m bench llm triage --model $MODEL --split dev --limit 1" \
  -- bash scripts/sb llm triage --model "$MODEL" --split dev --limit 1
render demo_triage "secaudit · LLM triage"

# 3. The audit report for one repository
"$PY" scripts/record_demo.py "$CASTS/demo_audit.cast" --height 46 --width 116 --line-delay 0.045 --hold 5 \
  --show "python -m bench audit show $ITEM --model $MODEL --reveal-gt" \
  -- bash scripts/sb audit show "$ITEM" --model "$MODEL" --reveal-gt --details 1
render demo_audit "secaudit · audit report"
