"""
Utils module - Backward compatibility layer

This module maintains backward compatibility with code that imports from src.utils.
New code should import directly from src.model_management.

Deprecated imports are forwarded to their new locations in model_management.
"""

# DEPRECATED: These imports are maintained for backward compatibility only.
# New code should use: from src.model_management import ...

# Re-export model management functions for backward compatibility
from src.model_management import (
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
