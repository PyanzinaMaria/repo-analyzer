#!/usr/bin/env bash
# Set up the analyzer toolchain on Linux x86-64 without sudo.
# Idempotent: re-running skips steps that are already done.
#   - project venv:   ~/.venvs/repo-analyzer  (Python 3.12, managed by uv; analyzer, worker, web, bench)
#   - analyzer venv:  ~/.venvs/sast      (semgrep, bandit[sarif])
#   - node:           ~/.local/node      (Node 22 LTS, official tarball)
#   - eslint deps:    <repo>/tools/eslint/node_modules
#   - codeql bundle:  ~/tools/codeql
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY_VERSION="${PY_VERSION:-3.12}"
NODE_MAJOR="${NODE_MAJOR:-22}"
SEMGREP_VERSION="${SEMGREP_VERSION:-}"   # empty = latest, then recorded in env.json
BANDIT_VERSION="${BANDIT_VERSION:-}"

command -v uv >/dev/null || curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$HOME/.local/node/bin:$HOME/tools/codeql:$PATH"

echo "== project venv"
VENV="${VENV:-$HOME/.venvs/repo-analyzer}"
if [ ! -x "$VENV/bin/python" ]; then
  uv venv --python "$PY_VERSION" "$VENV"
fi
VIRTUAL_ENV="$VENV" uv pip install -r "$REPO/requirements-bench.txt" -r "$REPO/frontend/web/requirements.lock"

echo "== analyzer venv"
if [ ! -x "$HOME/.venvs/sast/bin/semgrep" ]; then
  uv venv --python "$PY_VERSION" "$HOME/.venvs/sast"
  VIRTUAL_ENV="$HOME/.venvs/sast" uv pip install \
    "semgrep${SEMGREP_VERSION:+==$SEMGREP_VERSION}" \
    "bandit[sarif]${BANDIT_VERSION:+==$BANDIT_VERSION}"
fi

echo "== node"
if [ ! -x "$HOME/.local/node/bin/node" ]; then
  base="https://nodejs.org/dist/latest-v${NODE_MAJOR}.x"
  tarball="$(curl -fsSL "$base/SHASUMS256.txt" | awk '/linux-x64.tar.xz$/ {print $2}')"
  tmp="$(mktemp -d)"
  curl -fsSL "$base/$tarball" -o "$tmp/$tarball"
  (cd "$tmp" && curl -fsSL "$base/SHASUMS256.txt" | grep " $tarball\$" | sha256sum -c -)
  mkdir -p "$HOME/.local/node"
  tar -xJf "$tmp/$tarball" -C "$HOME/.local/node" --strip-components=1
  rm -rf "$tmp"
fi

echo "== eslint deps"
# node_modules must live on the Linux filesystem (fast, no NTFS symlink issues),
# so install into ~/.cache/secbench-eslint and point the runner at it.
ESLINT_HOME="$HOME/.cache/secbench-eslint"
mkdir -p "$ESLINT_HOME"
cp "$REPO/tools/eslint/package.json" "$REPO/tools/eslint/package-lock.json" "$ESLINT_HOME/" 2>/dev/null || \
  cp "$REPO/tools/eslint/package.json" "$ESLINT_HOME/"
cp "$REPO/tools/eslint/eslint.config.mjs" "$ESLINT_HOME/"
(cd "$ESLINT_HOME" && if [ -f package-lock.json ]; then npm ci --no-audit --no-fund; else npm install --no-audit --no-fund; fi)
[ -f "$REPO/tools/eslint/package-lock.json" ] || cp "$ESLINT_HOME/package-lock.json" "$REPO/tools/eslint/"

echo "== codeql"
if [ ! -x "$HOME/tools/codeql/codeql" ]; then
  mkdir -p "$HOME/tools"
  tmp="$(mktemp -d)"
  curl -fsSL https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz \
    -o "$tmp/codeql.tgz"
  tar -xzf "$tmp/codeql.tgz" -C "$HOME/tools"
  rm -rf "$tmp"
fi

echo "== versions"
"$HOME/.venvs/sast/bin/semgrep" --version
"$HOME/.venvs/sast/bin/bandit" --version | head -1
node --version
(cd "$ESLINT_HOME" && npx eslint --version)
codeql version --format=terse
