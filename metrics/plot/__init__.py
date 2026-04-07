"""
Metrics visualization and reporting module.

Provides interactive Plotly charts, PNG exports, and unified HTML reports.
"""

from .plot_generator import MetricsPlotter, PlotlyTheme, THEME_COLORS, MODEL_COLORS, SIMILARITY_COLORS
from .report_generator import ReportGenerator

__all__ = [
    'MetricsPlotter',
    'PlotlyTheme',
    'ReportGenerator',
    'THEME_COLORS',
    'MODEL_COLORS',
    'SIMILARITY_COLORS',
]
