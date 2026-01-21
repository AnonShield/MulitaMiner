"""
Funções de matching fuzzy para pareamento de vulnerabilidades.
"""
from rapidfuzz import fuzz, process
from typing import List, Tuple, Optional


def best_fuzzy_match(name_norm: str, baseline_norm_names: List[str]) -> Tuple[Optional[str], float]:
    """
    Retorna (match_norm, score) usando RapidFuzz (muito mais rápido que SequenceMatcher).
    
    Args:
        name_norm: Nome normalizado da vulnerabilidade
        baseline_norm_names: Lista de nomes normalizados da baseline
        
    Returns:
        Tupla (melhor_match, score) onde score está entre 0.0 e 1.0
    """
    if not name_norm or not baseline_norm_names:
        return None, 0.0
    
    # process.extractOne retorna (match, score, index) ou None
    result = process.extractOne(
        name_norm, 
        baseline_norm_names, 
        scorer=fuzz.ratio,
        score_cutoff=0  # Não filtramos aqui, deixamos para o threshold depois
    )
    
    if result:
        best_name, score_int, _ = result
        return best_name, score_int / 100.0  # Normaliza de 0-100 para 0-1
    
    return None, 0.0
