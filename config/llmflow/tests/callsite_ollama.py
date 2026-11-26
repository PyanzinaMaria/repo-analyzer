# semgrep --test snippets for config/llmflow/sdks/ollama.yaml (call-site rules)
import ollama
from ollama import Client, chat


class Local:
    def __init__(self, host):
        self.client = ollama.Client(host=host)

    def ask(self, msgs):
        # ruleid: llmflow.callsite.ollama.client.chat
        return self.client.chat(model="llama3.1", messages=msgs, stream=False)

    def complete(self, text):
        # ruleid: llmflow.callsite.ollama.client.generate
        return self.client.generate(model="llama3.1", prompt=text)


def module_level(msgs, text):
    # ruleid: llmflow.callsite.ollama.chat
    ollama.chat(model="llama3.1", messages=msgs, tools=[])
    # ruleid: llmflow.callsite.ollama.chat
    chat("qwen2.5", msgs)
    # ruleid: llmflow.callsite.ollama.generate
    ollama.generate("llama3.1", text)
    # ruleid: llmflow.callsite.ollama.client.chat
    Client().chat(model="llama3.1", messages=msgs)


def chat_without_model_kwargs(room, text):
    # ok: llmflow.callsite.ollama.client.chat
    room.chat(text)
