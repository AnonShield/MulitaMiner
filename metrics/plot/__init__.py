"""Metrics visualization and reporting module.

Public API:
    themes        — design tokens (palette, motion, thresholds)
    Dataset       — typed container for chart input data
    load_dataset  — read aggregated_metrics.xlsx + per-run files
    build_report  — write the full HTML report
    export_all    — write the PNG figures used in the paper
"""

from . import themes
from .data_source import Dataset, load_dataset
from .report import build_report
from .png import export_all

__all__ = ["themes", "Dataset", "load_dataset", "build_report", "export_all"]
