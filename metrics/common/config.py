"""
Configuration shared between metrics.
"""
from pathlib import Path

# Baseline directory (project root)
BASELINE_DIR = Path(__file__).parents[1] / "baselines"

# Threshold for fuzzy matching
FUZZY_THRESHOLD = 0.85

# Common typo corrections
FIX_COMMON_TYPOS = {
    "certicate": "certificate",
    "extaction": "extraction",
}

# Sparse fields that should not count as perfect match when both empty
SPARSE_FIELDS = {"plugin"}

# Default extraction sheets to compare
DEFAULT_EXTRACTION_SHEETS = [
    "Extração DEEPSEEK",
    "Extração GPT4", 
    "Extração GPT4.1",
    "Extração GPT5",
    "Extração LLAMA3",
    "Extração LLAMA4"
]
