"""
Utils module - Backward compatibility layer

This module maintains backward compatibility with code that imports from mulitaminer.utils.
New code should import directly from mulitaminer.llm.

Deprecated imports are forwarded to their new locations in mulitaminer.llm.
"""

# DEPRECATED: These imports are maintained for backward compatibility only.
# New code should use: from mulitaminer.llm import ...

# Re-export model management functions for backward compatibility
from mulitaminer.llm import (
    load_llm,
    load_profile,
    get_tokenizer,
    count_tokens,
    init_llm,
    validate_json_and_tokens,
    parse_json_response,
    validate_and_normalize_vulnerability,
    load_prompt,
)

__all__ = [
    'load_llm',
    'load_profile',
    'get_tokenizer',
    'count_tokens',
    'init_llm',
    'validate_json_and_tokens',
    'parse_json_response',
    'validate_and_normalize_vulnerability',
    'load_prompt',
]
