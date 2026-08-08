"""Text sanitization and LLM response content extraction."""

import re
import unicodedata
from typing import List, Dict, Any

_THINK_BLOCK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_OPEN_THINK_RE = re.compile(r"<think>.*", re.DOTALL | re.IGNORECASE)

def normalize_ligatures(text: str) -> str:
    """Split PDF ligatures into separate characters via NFKC (U+FB01 -> fi)."""
    if not text:
        return text
    return unicodedata.normalize('NFKC', text)


def sanitize_unicode_text(text: str) -> str:
    """Replace Unicode characters that raise UnicodeEncodeError on Windows."""
    if not text:
        return text

    result = normalize_ligatures(text)

    replacements = {
        '\u2717': '[X]',          # ✗ (checkmark)
        '\u2713': '[V]',          # ✓ (checkmark)
        '\u2022': '*',            # • (bullet)
        '\u00b7': '*',            # · (middle dot)
        '\u2023': '→',            # ‣ (triangular bullet)
        '\u2010': '-',            # ‐ (hyphen)
        '\u2011': '-',            # ‑ (non-breaking hyphen)
        '\u2012': '-',            # ‒ (figure dash)
        '\u2013': '-',            # – (en dash)
        '\u2014': '-',            # — (em dash)
        '\u2015': '-',            # ― (horizontal bar)
        '\u2018': "'",            # ' (left single quote)
        '\u2019': "'",            # ' (right single quote)
        '\u201c': '"',            # " (left double quote)
        '\u201d': '"',            # " (right double quote)
    }
    
    for problematic, replacement in replacements.items():
        result = result.replace(problematic, replacement)

    # Non-ASCII survives only as letters, numbers, spaces or basic punctuation
    clean_chars = []
    for char in result:
        try:
            char.encode('ascii', 'strict')
            clean_chars.append(char)
        except (UnicodeEncodeError, UnicodeDecodeError):
            category = unicodedata.category(char)
            if category[0] in ['L', 'N'] or char.isspace() or char in ',.!?;:-':
                clean_chars.append(char)

    return ''.join(clean_chars)


def extract_response_content(response) -> str:
    """Get the text out of an LLM response (string or LangChain object).

    Strips <think>...</think> blocks from reasoning models so JSON parsing
    downstream sees only the answer.
    """
    if response is None:
        return ""
    if isinstance(response, str):
        content = response
    elif hasattr(response, 'content'):
        content = response.content or ""
    else:
        content = str(response)

    content = _THINK_BLOCK_RE.sub("", content)
    content = _OPEN_THINK_RE.sub("", content)
    return content.strip()