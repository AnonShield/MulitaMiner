"""
Processing of chunks and vulnerabilities.
Contains tokenization, splitting, retry and consolidation logic.
"""

import unicodedata
from typing import List, Dict, Any
from .chunking import validate_base_instances_pairs


def normalize_ligatures(text: str) -> str:
    """
    Normalize typographic ligatures into separate characters.
    
    PDFs often use ligatures (ﬁ, ﬂ, etc.) which are single characters.
    NFKC decomposes these ligatures into separate characters:
    - ﬁ (U+FB01) → fi
    - ﬂ (U+FB02) → fl
    - ﬀ (U+FB00) → ff
    - ﬃ (U+FB03) → ffi
    - ﬄ (U+FB04) → ffl
    """
    if not text:
        return text
    return unicodedata.normalize('NFKC', text)


def sanitize_unicode_text(text: str) -> str:
    """
    Remove/replace problematic Unicode characters that cannot be encoded on Windows.
    
    Keeps text readable but removes special symbols that cause UnicodeEncodeError.
    """
    if not text:
        return text
    
    # PRIMEIRO: Normaliza ligaduras (ﬁ → fi, ﬂ → fl, etc.)
    result = normalize_ligatures(text)
    
    # Common character replacements for problematic characters
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
    
    # Remove control characters and other problematic ones
    # Keep letters, numbers, basic punctuation and spaces
    clean_chars = []
    for char in result:
        try:
            # Try to encode in UTF-8 and then ASCII
            char.encode('ascii', 'strict')
            clean_chars.append(char)
        except (UnicodeEncodeError, UnicodeDecodeError):
            # If unable to get ASCII, try gentler approach
            category = unicodedata.category(char)
            # Keep letters (L*), numbers (N*), space (Zs)
            if category[0] in ['L', 'N'] or char.isspace() or char in ',.!?;:-':
                clean_chars.append(char)
            # Otherwise, ignore
    
    return ''.join(clean_chars)