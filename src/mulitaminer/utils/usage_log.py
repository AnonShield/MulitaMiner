"""Captura do usage REAL retornado pela API (DeepSeek/OpenAI).

Grava por chamada em results_tokens/usage_real_<pid>.jsonl:
  {llm, input_tokens, output_tokens, cache_hit_tokens, cache_miss_tokens}

Aditivo e defensivo: nunca levanta exceção, nunca afeta a chamada da LLM.
Deve ser chamado no provider, com o objeto de resposta (AIMessage) — ANTES de
reduzir a resposta a .content.
"""
from __future__ import annotations

import os
import json


def log_real_usage(response, llm_name):
    try:
        um = getattr(response, "usage_metadata", None) or {}
        rmeta = getattr(response, "response_metadata", None) or {}
        tu = rmeta.get("token_usage") or rmeta.get("usage") or {}
        rec = {
            "llm": llm_name,
            "target": os.environ.get("MULITA_TARGET"),   # baseline (setado no main.py)
            "run": os.environ.get("MULITA_RUN"),          # rótulo do run (baseline_llm_runN)
            "input_tokens": um.get("input_tokens"),
            "output_tokens": um.get("output_tokens"),
            "cache_hit_tokens": tu.get("prompt_cache_hit_tokens"),
            "cache_miss_tokens": tu.get("prompt_cache_miss_tokens"),
        }
        if rec["input_tokens"] is None and rec["output_tokens"] is None:
            return  # provider não expôs usage
        os.makedirs("results_tokens", exist_ok=True)
        with open(os.path.join("results_tokens", f"usage_real_{os.getpid()}.jsonl"),
                  "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass
