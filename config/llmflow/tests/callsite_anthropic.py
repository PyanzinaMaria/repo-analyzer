# semgrep --test snippets for config/llmflow/sdks/anthropic.yaml (call-site rules)
import anthropic
from anthropic import Anthropic
from openai import OpenAI

client = Anthropic()


def chat(msgs, system):
    # ruleid: llmflow.callsite.anthropic.messages
    client.messages.create(model="claude-3-5-sonnet-latest", max_tokens=512, system=system, messages=msgs)
    # ruleid: llmflow.callsite.anthropic.messages
    client.beta.messages.create(model="claude-3-5-sonnet-latest", max_tokens=512, messages=msgs)
    # ruleid: llmflow.callsite.anthropic.messages
    anthropic.Anthropic().messages.create(model="claude-3-5-sonnet-latest", max_tokens=64, messages=msgs)
    # ruleid: llmflow.callsite.anthropic.messages.stream
    with client.messages.stream(model="claude-3-5-sonnet-latest", max_tokens=512, messages=msgs) as s:
        return s.get_final_text()


def assistants_api_is_not_a_model_call(thread_id, text):
    oai = OpenAI()
    # ok: llmflow.callsite.anthropic.messages
    oai.beta.threads.messages.create(thread_id, role="user", content=text)
