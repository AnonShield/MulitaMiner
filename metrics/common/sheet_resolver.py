"""Resolve the baseline sheet name across known variants.

Accepts baseline workbooks that use either "Vulnerabilities" (canonical) or
"Sheet1" (default openpyxl sheet name kept on some generated baselines).
"""
from typing import Iterable
import pandas as pd

BASELINE_SHEET = ("Vulnerabilities", "Sheet1")


def resolve_baseline_sheet(excel_file: pd.ExcelFile, candidates: Iterable[str] = BASELINE_SHEET) -> str:
    available = excel_file.sheet_names
    for name in candidates:
        if name in available:
            return name
    raise ValueError(
        f"None of the expected baseline sheet names {list(candidates)} were found. "
        f"Available sheets: {available}"
    )
