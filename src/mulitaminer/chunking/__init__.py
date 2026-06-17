"""Chunking: split block text into LLM-sized chunks and process them.

Public API is re-exported here so callers use ``from mulitaminer.chunking import X``
regardless of which submodule (tokens/retry/errors) X lives in.
"""
from mulitaminer.chunking.tokens import (
    TokenChunk,
    get_token_based_chunks,
    build_prompt,
    detect_scanner_pattern,
    split_text_to_subchunks,
    smart_chunk_vulnerabilities,
    intelligent_chunk_redivision,
)
from mulitaminer.chunking.retry import (
    retry_chunk_with_subdivision,
    robust_chunk_processing,
)

__all__ = [
    "TokenChunk",
    "get_token_based_chunks",
    "build_prompt",
    "detect_scanner_pattern",
    "split_text_to_subchunks",
    "smart_chunk_vulnerabilities",
    "intelligent_chunk_redivision",
    "retry_chunk_with_subdivision",
    "robust_chunk_processing",
]
