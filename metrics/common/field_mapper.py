"""
Field Category Mapper - Centralized field configuration for metrics

Maps fields to either deterministic (Entity Metrics) or semantic (BERT/ROUGE) analysis.
Provides utilities for normalizing field values and filtering fields by category.
"""
import json
import os
from pathlib import Path
from typing import Dict, List, Set


def load_field_categories() -> Dict[str, List[str]]:
    """Load field categories from config JSON."""
    config_path = Path(__file__).parents[2] / 'src' / 'configs' / 'schema' / 'field_categories.json'
    
    if not config_path.exists():
        raise FileNotFoundError(f"Field categories config not found: {config_path}")
    
    with open(config_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def get_deterministic_fields(baseline_columns: List[str]) -> Set[str]:
    """
    Get deterministic fields that exist in the baseline.
    
    Args:
        baseline_columns: List of column names from baseline
    
    Returns:
        Set of deterministic field names (lowercase, filtered to exist in baseline)
    """
    config = load_field_categories()
    deterministic = {f.lower() for f in config['deterministic']}
    baseline_lower = {c.lower() for c in baseline_columns}
    
    # Return intersection (only fields that exist in both)
    return deterministic & baseline_lower


def get_semantic_fields(baseline_columns: List[str]) -> Set[str]:
    """
    Get semantic fields that exist in the baseline.
    
    Args:
        baseline_columns: List of column names from baseline
    
    Returns:
        Set of semantic field names (lowercase, filtered to exist in baseline)
    """
    config = load_field_categories()
    semantic = {f.lower() for f in config['semantic']}
    excluded = {f.lower() for f in config['excluded']}
    baseline_lower = {c.lower() for c in baseline_columns}
    
    # Return: (semantic fields AND in baseline) AND NOT excluded
    return (semantic & baseline_lower) - excluded


def get_excluded_fields() -> Set[str]:
    """Get set of fields that should be excluded from analysis."""
    config = load_field_categories()
    return {f.lower() for f in config['excluded']}


def get_actual_column_name(field_lower: str, baseline_columns: List[str]) -> str:
    """
    Get the actual column name from baseline (preserves original casing).
    
    Args:
        field_lower: Field name in lowercase
        baseline_columns: List of actual column names
    
    Returns:
        Actual column name from baseline, or field_lower if not found
    """
    for col in baseline_columns:
        if col.lower() == field_lower:
            return col
    return field_lower


def normalize_field_value(value, field_name: str = None) -> str:
    """
    Normalize field value for comparison.
    
    Special handling:
    - port: extract digits only
    - All others: strip whitespace, convert to lowercase
    
    Args:
        value: Value to normalize
        field_name: Field name (for special handling)
    
    Returns:
        Normalized value as string
    """
    if value is None or (isinstance(value, float) and value != value):  # NaN check
        return ""
    
    value_str = str(value).strip()
    
    # Special case: port numbers
    if field_name and field_name.lower() == 'port':
        # Remove commas/dots and keep only digits
        value_str = value_str.replace(',', '').replace('.', '')
        if value_str.isdigit() or value_str.lower() == 'general':
            return value_str
        return ""

    # Special case: cvss — normalize int vs float representations (7, 7.0, 7.00 → '7')
    if field_name and field_name.lower() == 'cvss':
        try:
            return f"{float(value_str):g}"
        except ValueError:
            return ""

    # Default: lowercase for all other fields
    return value_str.lower()


def build_field_map(baseline_columns: List[str]) -> Dict[str, str]:
    """
    Build mapping from lowercase field names to actual baseline column names.
    
    Args:
        baseline_columns: List of actual column names from baseline
    
    Returns:
        Dict mapping lowercase field names to actual column names
    """
    field_map = {}
    baseline_lower = {col.lower(): col for col in baseline_columns}
    
    config = load_field_categories()
    all_fields = config['deterministic'] + config['semantic']
    
    for field in all_fields:
        field_lower = field.lower()
        if field_lower in baseline_lower:
            field_map[field_lower] = baseline_lower[field_lower]
    
    return field_map
