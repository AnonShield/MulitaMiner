"""Pipelines orchestrate I/O, alignment and scoring.

Each pipeline is a thin script that:
    1. Loads inputs (JSON / XLSX)
    2. Optionally aligns extraction ↔ baseline (for field-level metrics)
    3. Calls scorers from ``metrics.scorers``
    4. Persists structured output (JSON / XLSX)

Pipelines do not implement metrics — they delegate to scorers — and they do
not handle aggregation across runs — that is ``metrics/aggregators/``.
"""
