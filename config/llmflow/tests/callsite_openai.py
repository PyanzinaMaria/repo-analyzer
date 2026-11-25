# semgrep --test snippets for config/llmflow/sdks/openai.yaml (call-site rules)
import openai
from openai import AsyncOpenAI, OpenAI

client = OpenAI()
aclient = AsyncOpenAI()


class Bot:
    def __init__(self):
        self.client = OpenAI()

    def reply(self, msgs):
        # ruleid: llmflow.callsite.openai.chat
        return self.client.chat.completions.create(model="gpt-4o", messages=msgs)


def all_apis(msgs, text):
    # ruleid: llmflow.callsite.openai.chat
    client.chat.completions.create(model="gpt-4o-mini", messages=msgs, tools=[])
    # ruleid: llmflow.callsite.openai.chat.parse
    client.beta.chat.completions.parse(model="gpt-4o", messages=msgs)
    # ruleid: llmflow.callsite.openai.chat.stream
    client.chat.completions.stream(model="gpt-4o", messages=msgs)
    # ruleid: llmflow.callsite.openai.responses
    client.responses.create(model="gpt-4o", input=text)
    # ruleid: llmflow.callsite.openai.completions
    client.completions.create(model="gpt-3.5-turbo-instruct", prompt=text)
    # ruleid: llmflow.callsite.openai.legacy.chat
    openai.ChatCompletion.create(model="gpt-4", messages=msgs)
    # ruleid: llmflow.callsite.openai.legacy.completion
    openai.Completion.create(model="text-davinci-003", prompt=text)


async def async_api(msgs):
    # ruleid: llmflow.callsite.openai.chat
    await aclient.chat.completions.create(model="gpt-4o", messages=msgs)
    # ruleid: llmflow.callsite.openai.legacy.chat.async
    await openai.ChatCompletion.acreate(model="gpt-4", messages=msgs)


def not_llm_calls(db, msgs):
    # ok: llmflow.callsite.openai.chat
    db.chat.create(messages=msgs)
    # ok: llmflow.callsite.openai.completions
    db.orders.create(prompt="x")
