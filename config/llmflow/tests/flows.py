# semgrep --test snippets for the generated taint rules (o2s / i2p / par families)
import os
import subprocess
import sqlite3

import anthropic
import ollama
from flask import Flask, request
from markupsafe import Markup
from openai import OpenAI

app = Flask(__name__)
client = OpenAI()
claude = anthropic.Anthropic()


def llm_to_shell():
    r = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": "list files"}])
    cmd = r.choices[0].message.content
    # ruleid: llmflow.o2s.sink.shell
    subprocess.run(cmd, shell=True)
    # ok: llmflow.o2s.sink.shell
    subprocess.run(["ls", "-la"])


def llm_to_sql():
    conn = sqlite3.connect("app.db")
    out = ollama.chat(model="llama3.1", messages=[{"role": "user", "content": "sql for top users"}])
    sql = out["message"]["content"].strip()
    # ruleid: llmflow.o2s.sink.sql
    conn.execute(sql)


def llm_to_eval_and_html():
    m = claude.messages.create(model="claude-3-5-sonnet-latest", max_tokens=100, messages=[])
    text = m.content[0].text
    # ruleid: llmflow.o2s.sink.code_eval
    eval(text)
    # ruleid: llmflow.o2s.sink.html, llmflow.o2s.return
    return Markup(text)


def wrapper():
    r = client.chat.completions.create(model="gpt-4o", messages=[])
    # ruleid: llmflow.o2s.return
    return r.choices[0].message.content


def stream_to_shell():
    stream = client.chat.completions.create(model="gpt-4o", messages=[], stream=True)
    text = ""
    for chunk in stream:
        text += chunk.choices[0].delta.content or ""
    # ruleid: llmflow.o2s.sink.shell
    os.system(text)


@app.route("/ask")
def route():
    question = request.args.get("q")
    messages = []
    messages.append({"role": "user", "content": question})
    # ruleid: llmflow.i2p.web_request.prompt
    client.chat.completions.create(model="gpt-4o", messages=messages)


def cli_prompt():
    text = input("> ")
    # ruleid: llmflow.i2p.cli.prompt
    ollama.generate("llama3.1", text)


def param_to_shell(command, verbose=False):
    # ruleid: llmflow.par.sink.shell
    subprocess.run(command, shell=True)


def param_to_prompt(user_text):
    # ruleid: llmflow.par.prompt, llmflow.o2s.return
    return claude.messages.create(model="claude-3-5-sonnet-latest", max_tokens=100, system=user_text, messages=[])


class Runner:
    def run_code(self, code: str):
        # ok: llmflow.par.sink.code_eval
        self.log("start")
        # ruleid: llmflow.par.sink.code_eval
        exec(code)

    def log(self, msg):
        pass
