"""
Processamento de chunks e vulnerabilidades.
Contém lógica de tokenização, splitting, retry e consolidação.
"""

import unicodedata
from typing import List, Dict, Any
from .chunking import validate_base_instances_pairs


def normalize_ligatures(text: str) -> str:
    """
    Normaliza ligaduras tipográficas em caracteres separados.
    
    PDFs frequentemente usam ligaduras (ﬁ, ﬂ, etc.) que são caracteres únicos.
    NFKC decompõe essas ligaduras em caracteres separados:
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
    Remove/substitui caracteres Unicode problemáticos que não podem ser codificados no Windows.
    
    Mantém texto legível mas remove símbolos especiais que causam UnicodeEncodeError.
    """
    if not text:
        return text
    
    # PRIMEIRO: Normaliza ligaduras (ﬁ → fi, ﬂ → fl, etc.)
    result = normalize_ligatures(text)
    
    # Substituições comuns de caracteres problemáticos
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
    
    # Remove caracteres de controle e outros problemáticos
    # Mantém letras, números, pontuação básica e espaços
    clean_chars = []
    for char in result:
        try:
            # Tenta encodar em UTF-8 e depois em ASCII
            char.encode('ascii', 'strict')
            clean_chars.append(char)
        except (UnicodeEncodeError, UnicodeDecodeError):
            # Se não consegue ASCII, tenta uma abordagem mais suave
            category = unicodedata.category(char)
            # Mantém letras (L*), números (N*), espaço (Zs)
            if category[0] in ['L', 'N'] or char.isspace() or char in ',.!?;:-':
                clean_chars.append(char)
            # Caso contrário, ignora
    
    return ''.join(clean_chars)