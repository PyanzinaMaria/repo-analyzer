"""Offline batch runner for Kaggle / Colab GPUs (vLLM).

1. Locally:   scripts/sb llm triage --model Qwen/Qwen2.5-Coder-14B-Instruct-AWQ --mode export
              -> $SECBENCH_DATA/llm_batch/Qwen_Qwen2.5-Coder-14B-Instruct-AWQ.requests.jsonl
2. Upload that file to a Kaggle notebook (GPU T4 x2 or P100) and run:
              !pip install -q vllm
              !python kaggle_vllm_batch.py requests.jsonl responses.jsonl --tp 2
3. Download responses.jsonl, then locally:
              scripts/sb llm import responses.jsonl
              scripts/sb llm triage --model ... --mode cache     # assembles outputs from the cache

The cache key is computed locally from (model, messages, params); this script only echoes it back.
Sampling uses the request's own params (temperature 0 by default).
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("requests")
    ap.add_argument("responses")
    ap.add_argument("--tp", type=int, default=1, help="tensor parallel size (2 for Kaggle T4 x2)")
    ap.add_argument("--max-model-len", type=int, default=16384)
    ap.add_argument("--model", default=None, help="override model (default: the model named in the requests)")
    args = ap.parse_args()

    from vllm import LLM, SamplingParams

    reqs = [json.loads(line) for line in open(args.requests, encoding="utf-8") if line.strip()]
    by_model = defaultdict(list)
    for r in reqs:
        by_model[args.model or r["model"]].append(r)

    with open(args.responses, "w", encoding="utf-8") as out:
        for model, rs in by_model.items():
            llm = LLM(model=model, tensor_parallel_size=args.tp, max_model_len=args.max_model_len,
                      gpu_memory_utilization=0.92, trust_remote_code=True)
            tok = llm.get_tokenizer()
            prompts, sps = [], []
            for r in rs:
                p = r.get("params", {})
                prompts.append(tok.apply_chat_template(r["messages"], tokenize=False, add_generation_prompt=True))
                sps.append(SamplingParams(temperature=p.get("temperature", 0.0),
                                          max_tokens=min(p.get("max_tokens", 2048), 4096)))
            for r, res in zip(rs, llm.generate(prompts, sps)):
                o = res.outputs[0]
                out.write(json.dumps({"key": r["key"], "model": r["model"], "text": o.text,
                                      "usage": {"prompt_tokens": len(res.prompt_token_ids),
                                                "completion_tokens": len(o.token_ids)}}) + "\n")
            del llm


if __name__ == "__main__":
    main()
