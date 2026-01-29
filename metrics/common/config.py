"""
Configurações compartilhadas entre métricas.
"""
from pathlib import Path

# Diretório de baselines (raiz do projeto)
BASELINE_DIR = Path(__file__).parents[1] / "baselines"

# Threshold para fuzzy matching
FUZZY_THRESHOLD = 0.85

# Correções de typos comuns
FIX_COMMON_TYPOS = {
    "certicate": "certificate",
    "extaction": "extraction",
}

# Campos esparsos que não devem contar como match perfeito quando ambos vazios
SPARSE_FIELDS = {"plugin"}

# Abas de extração padrão para comparar
DEFAULT_EXTRACTION_SHEETS = [
    "Extração DEEPSEEK",
    "Extração GPT4", 
    "Extração GPT4.1",
    "Extração GPT5",
    "Extração LLAMA3",
    "Extração LLAMA4"
]
