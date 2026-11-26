# semgrep --test snippets for config/llmflow/hygiene.yaml
import json
import logging
import subprocess

import httpx
import openai
from flask import request
from openai import OpenAI

log = logging.getLogger(__name__)

# ruleid: llmflow.hygiene.hardcoded-api-key, llmflow.hygiene.client-no-timeout
bad = OpenAI(api_key="sk-test-1234")
# ruleid: llmflow.hygiene.tls-verify-disabled
insecure = OpenAI(timeout=30, http_client=httpx.Client(verify=False))
# ruleid: llmflow.hygiene.plaintext-base-url
remote = OpenAI(timeout=30, base_url="http://10.0.0.5:8000/v1")
# ok: llmflow.hygiene.plaintext-base-url
local = OpenAI(timeout=30, base_url="http://localhost:8000/v1")
# ok: llmflow.hygiene.client-no-timeout
good = OpenAI(timeout=30)


def handler():
    topic = request.args.get("topic")
    # ruleid: llmflow.hygiene.no-max-tokens
    r = good.chat.completions.create(
        model="gpt-4o",
        # ruleid: llmflow.hygiene.untrusted-in-system-role
        messages=[{"role": "system", "content": f"You are an expert in {topic}"}],
    )
    # ruleid: llmflow.hygiene.response-logged
    log.info("answer: %s", r.choices[0].message.content)
    # ok: llmflow.hygiene.no-max-tokens
    good.chat.completions.create(model="gpt-4o", messages=[], max_tokens=200)
    # ruleid: llmflow.hygiene.user-controlled-model
    good.chat.completions.create(model=request.args.get("model"), messages=[], max_tokens=10)


def dispatch(tool_call, funcs):
    fn = funcs[tool_call.function.name]
    # ruleid: llmflow.hygiene.tool-args-unvalidated
    return fn(**json.loads(tool_call.function.arguments))


def run(cmd):
    # ruleid: llmflow.hygiene.shell-true-in-llm-module
    return subprocess.run(cmd, shell=True)
