"""Standardized XLSX read/write helpers shared across metric pipelines.

The bert/rouge/entity scripts each repeat the same Excel boilerplate
(open file, resolve sheet name, create writer, write multiple sheets).
This module centralizes it so pipelines stay focused on the metric logic.

Public API:
    load_baseline(path)   — read the baseline XLSX, picking the right sheet
    load_extraction(path) — same, for extraction XLSX
    write_xlsx(path, sheets) — write a multi-sheet XLSX in one call
"""
from __future__ import annotations

from pathlib import Path
from typing import Mapping, Union

import pandas as pd

from metrics.common.sheet_resolver import resolve_baseline_sheet


def _read_resolved(path: Union[str, Path]) -> pd.DataFrame:
    """Open ``path`` and read the sheet that ``resolve_baseline_sheet`` picks.

    Used for both baselines and extractions because they share the
    "Vulnerabilities" / "Sheet1" convention. Kept as one helper to avoid
    duplicating the ExcelFile dance.
    """
    path = Path(path)
    xls = pd.ExcelFile(path, engine="openpyxl")
    return pd.read_excel(path, sheet_name=resolve_baseline_sheet(xls), engine="openpyxl")


def load_baseline(path: Union[str, Path]) -> pd.DataFrame:
    """Read the baseline XLSX. Resolves the canonical sheet automatically."""
    return _read_resolved(path)


def load_extraction(path: Union[str, Path]) -> pd.DataFrame:
    """Read the extraction XLSX. Resolves the canonical sheet automatically."""
    return _read_resolved(path)


def write_xlsx(path: Union[str, Path], sheets: Mapping[str, pd.DataFrame]) -> Path:
    """Write a multi-sheet XLSX in one call.

    Creates parent directories if needed. Index is written for sheets
    that have a non-default index (typical for confusion matrices), and
    skipped otherwise — matching what each pipeline did inline.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with pd.ExcelWriter(path) as writer:
        for sheet_name, df in sheets.items():
            with_index = df.index.name is not None and df.index.name != "index"
            df.to_excel(writer, sheet_name=sheet_name, index=with_index)
    return path
