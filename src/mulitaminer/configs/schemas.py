"""Pydantic schemas for config validation (fail-fast on malformed JSON).

Validation only: ``load_llm`` / ``load_profile`` still return plain dicts (the
whole codebase consumes them via ``.get()``); they just refuse to return a
config that would otherwise blow up with a cryptic ``AttributeError`` several
frames later. ``extra="allow"`` keeps rich/optional fields working — only the
genuinely-essential fields are required and type-checked.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class LLMConfig(BaseModel):
    # extra="allow": don't reject configs carrying extra/provider-specific keys.
    # protected_namespaces=(): allow a field literally named ``model``.
    model_config = ConfigDict(extra="allow", protected_namespaces=())

    model: str
    provider: str | None = None
    endpoint: str | None = None
    api_key: str | None = None
    temperature: float | None = None
    max_tokens: int | None = None
    max_completion_tokens: int | None = None
    max_chunk_size: int | None = None
    reserve_for_response: int | None = None
    timeout: int | None = None
    options: dict | None = None
    tokenizer: dict | None = None
    # Reasoning toggles are provider-specific: bool on some, a level string
    # (e.g. "low"/"high") on others (gpt-oss). Accept either.
    disable_thinking: str | bool | None = None
    think: str | bool | None = None


class ScannerConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    prompt_template: str
    reader: str | None = None
    retry_attempts: int | None = None
    delay_between_chunks: int | None = None
    output_file: str | None = None
    consolidation_field: str | None = None
    merge_instances_with_same_base: bool | None = None
    chunking: dict | None = None
