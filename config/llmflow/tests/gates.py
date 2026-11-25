# semgrep --test snippets for config/llmflow/gates.yaml
import html
import re
import shlex
import sqlite3

import click

ALLOWED_COMMANDS = {"ls", "pwd"}


def allowlist(cmd):
    # ruleid: llmflow.gate.allowlist
    if cmd.split()[0] not in ALLOWED_COMMANDS:
        raise PermissionError(cmd)


def quoting(arg):
    # ruleid: llmflow.gate.shlex-quote
    return "ls " + shlex.quote(arg)


def escaping(text):
    # ruleid: llmflow.gate.html-escape
    return html.escape(text)


def readonly():
    # ruleid: llmflow.gate.sql-readonly
    return sqlite3.connect("file:app.db?mode=ro", uri=True)


def confirm(cmd):
    # ruleid: llmflow.gate.human-confirm
    if click.confirm(f"run {cmd}?"):
        return True
    # ruleid: llmflow.gate.human-confirm
    if input("run? [y/N] ").lower() == "y":
        return True


def weak(sql):
    # ruleid: llmflow.gate.prefix-check
    if not sql.strip().upper().startswith("SELECT"):
        return None
    # ruleid: llmflow.gate.regex-check
    if re.match(r"^[a-z]+$", sql):
        return sql


def not_gates(items, name):
    # ok: llmflow.gate.allowlist
    if name in items:
        return True
