# semgrep --test snippets for config/llmflow/frameworks/*.yaml (opt-in framework call sites)
import litellm
from sklearn.linear_model import LinearRegression


class MathChain:
    def _call(self, inputs):
        llm_executor = LLMChain(prompt=PROMPT, llm=self.llm)
        # ruleid: llmflow.callsite.langchain.predict, llmflow.callsite.llama_index.predict
        t = llm_executor.predict(question=inputs["q"], stop=["```output"])
        # ruleid: llmflow.callsite.langchain.chain.run
        u = self.llm_chain.run(inputs["q"])
        # ruleid: llmflow.callsite.langchain.llm.call
        v = self.llm(inputs["q"])
        # ruleid: llmflow.callsite.langchain.invoke
        w = chat_model.invoke(inputs["q"])
        # ruleid: llmflow.callsite.langchain.stream
        chunks = list(self.chain.stream(inputs))
        return t, u, v, w, chunks


def llama(service_context, query_engine, prompt):
    # ruleid: llmflow.callsite.llama_index.predict, llmflow.callsite.langchain.predict
    a = service_context.llm_predictor.predict(prompt)
    # ruleid: llmflow.callsite.llama_index.complete
    b = llm.complete(prompt)
    # ruleid: llmflow.callsite.llama_index.query
    c = query_engine.query(prompt)
    return a, b, c


def gateway(msgs):
    # ruleid: llmflow.callsite.litellm.completion
    return litellm.completion(model="gpt-4o", messages=msgs)


def not_llm(X, y, client, msgs, proc):
    model = LinearRegression().fit(X, y)
    # ok: llmflow.callsite.langchain.predict
    model.predict(X)
    # ok: llmflow.callsite.langchain.chain.run
    proc.run()
    # ok: llmflow.callsite.langchain.stream
    client.completions.stream(msgs)
