"""Record the token usage the API itself reports, one line per call.

Called from the provider with the raw response object, before it is reduced to
.content. Never raises: usage accounting must not break an extraction.
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
            "target": os.environ.get("MULITA_TARGET"),
            "run": os.environ.get("MULITA_RUN"),
            "input_tokens": um.get("input_tokens"),
            "output_tokens": um.get("output_tokens"),
            "cache_hit_tokens": tu.get("prompt_cache_hit_tokens"),
            "cache_miss_tokens": tu.get("prompt_cache_miss_tokens"),
        }
        if rec["input_tokens"] is None and rec["output_tokens"] is None:
            return  # provider reported no usage
        os.makedirs("results_tokens", exist_ok=True)
        with open(os.path.join("results_tokens", f"usage_real_{os.getpid()}.jsonl"),
                  "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass
