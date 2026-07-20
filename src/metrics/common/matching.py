"""
Funções de matching fuzzy para pareamento de vulnerabilidades.
"""
from rapidfuzz import fuzz, process
from typing import List, Tuple, Optional


def best_fuzzy_match(name_norm: str, baseline_norm_names: List[str]) -> Tuple[Optional[str], float]:
    """
    Return (match_norm, score) using RapidFuzz (much faster than SequenceMatcher).
    
    Args:
        name_norm: Nome normalizado da vulnerabilidade
        baseline_norm_names: Lista de nomes normalizados da baseline
        
    Returns:
        Tuple (best_match, score) where score is between 0.0 and 1.0
    """
    if not name_norm or not baseline_norm_names:
        return None, 0.0
    
    # process.extractOne returns (match, score, index) or None
    result = process.extractOne(
        name_norm, 
        baseline_norm_names, 
        scorer=fuzz.ratio,
        score_cutoff=0  # Do not filter here, leave for threshold later
    )
    
    if result:
        best_name, score_int, _ = result
        return best_name, score_int / 100.0  # Normalize from 0-100 to 0-1
    
    return None, 0.0
