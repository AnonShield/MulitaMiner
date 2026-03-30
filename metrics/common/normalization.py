"""
Funções de normalização de texto para comparação de vulnerabilidades.
"""
import re
import pandas as pd
from typing import Dict
from .config import FIX_COMMON_TYPOS


def normalize_name(s: str) -> str:
    """Normaliza nome de vulnerabilidade para maximizar o pareamento."""
    if pd.isna(s):
        return ""
    s0 = str(s)
    s1 = s0.strip()
    # Corrige typos comuns
    low = s1.lower()
    for a, b in FIX_COMMON_TYPOS.items():
        low = low.replace(a, b)
    # Remove multiple spaces
    low = re.sub(r"\s+", " ", low)
    return low


def normalize_field_data(val) -> str:
    """Advanced normalization to ensure consistent comparison between baseline and extraction."""
    # Check if it's list/tuple first (before pd.isna)
    if isinstance(val, (list, tuple)):
        # Converte lista em texto separado por pontos
        clean_items = []
        for item in val:
            item_str = str(item).strip()
            if item_str and item_str.lower() not in ['none', 'null', '']:
                clean_items.append(item_str)
        text = ". ".join(clean_items) if clean_items else ""
    elif pd.isna(val):
        return ""
    else:
        # Converter para string primeiro
        text = str(val).strip()
        
        # Se parece com lista/array em formato string
        if (text.startswith('[') and text.endswith(']')) or (text.startswith('(') and text.endswith(')')):
            try:
                import ast
                parsed = ast.literal_eval(text)
                if isinstance(parsed, (list, tuple, set)):
                    # Converte lista em texto separado por pontos
                    clean_items = []
                    for item in parsed:
                        item_str = str(item).strip()
                        if item_str and item_str.lower() not in ['none', 'null', '']:
                            clean_items.append(item_str)
                    text = ". ".join(clean_items) if clean_items else ""
            except (ValueError, SyntaxError):
                # Se falhar o parse, trata como string normal
                text = text.strip('[]()').replace("'", "").replace('"', '')
                text = text.replace(',', ', ')
    
    # Standard text normalization
    text = text.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    text = text.replace("\t", " ")
    
    # Remove special formatting characters
    text = text.replace("•", " ").replace("\u2022", " ")
    text = text.replace("–", "-").replace("—", "-")
    
    # Normalize multiple spaces
    text = re.sub(r"\s+", " ", text).strip()
    
    # Remove redundant punctuation
    text = re.sub(r"[.]{2,}", ".", text)  # Multiple dots
    text = re.sub(r"[,]{2,}", ",", text)  # Multiple commas
    
    # Remove redundant punctuation at end
    text = text.rstrip(' .,;:')
    
    return text
