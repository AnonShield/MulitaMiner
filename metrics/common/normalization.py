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
    # remove espaços múltiplos
    low = re.sub(r"\s+", " ", low)
    return low


def normalize_field_data(val) -> str:
    """Normalização avançada para garantir comparação consistente entre baseline e extração."""
    # Verificar se é lista/tupla primeiro (antes de pd.isna)
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
    
    # Normalização de texto padrão
    text = text.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    text = text.replace("\t", " ")
    
    # Remove caracteres especiais de formatação
    text = text.replace("•", " ").replace("\u2022", " ")
    text = text.replace("–", "-").replace("—", "-")
    
    # Normaliza espaços múltiplos
    text = re.sub(r"\s+", " ", text).strip()
    
    # Remove pontuação redundante
    text = re.sub(r"[.]{2,}", ".", text)  # múltiplos pontos
    text = re.sub(r"[,]{2,}", ",", text)  # múltiplas vírgulas
    
    # Remove pontuação no final se redundante
    text = text.rstrip(' .,;:')
    
    return text
