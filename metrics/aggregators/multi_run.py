"""Aggregate per-run metrics into mean ± std tables (metrics.md §5).

Walks one or more result roots (``results_runs/``, ``results_runs_V2/``)
via :mod:`metrics.aggregators.discovery`, reads the per-run summary
sheets, and emits two tidy tables:

    long_df  — one row per (version, target, model, run, source, field, metric)
    agg_df   — one row per (version, target, model, source, field, metric)
               with mean, std, min, max, n

Sources collected (whatever exists in the run dir):
    bert     → Summary sheet of bert_comparison_*.xlsx
    rouge    → Summary sheet of rouge_comparison_*.xlsx
    entity   → Summary sheet of entity_metrics_*.xlsx
    severity → Summary sheet of severity_confusion_*.xlsx
    coverage → Summary + Per_Field of coverage_*.xlsx
    schema   → JSON file (top-level scalar fields)

Usage::

    python -m metrics.aggregators.multi_run
        --root results_runs results_runs_V2
        --output aggregated_metrics.xlsx
"""
from __future__ import annotations

import argparse
import io
import json
import os
import sys
from pathlib import Path
from typing import Iterable

# UTF-8 stdout on Windows (consistency with other pipelines).
if sys.platform.startswith("win") and sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")
    os.environ["PYTHONIOENCODING"] = "utf-8"

sys.path.insert(0, str(Path(__file__).parents[2]))

import pandas as pd  # noqa: E402

from metrics.aggregators.discovery import RunArtifacts, discover_runs  # noqa: E402

# Columns shared by every long-format row.
_KEY_COLS = ("version", "target", "model", "run", "source", "field", "metric")


# ---------------------------------------------------------------------------
# Per-source readers — each returns a list of dicts in long format.
# ---------------------------------------------------------------------------

def _emit(run: RunArtifacts, source: str, field: str, metric: str, value) -> dict:
    return {
        "version": run.version, "target": run.target, "model": run.model,
        "run": run.run, "source": source, "field": field,
        "metric": metric, "value": value,
    }


def _read_summary_xlsx(path: Path, source: str, run: RunArtifacts,
                       value_columns: Iterable[str], field_col: str = "Column") -> list[dict]:
    """Read ``Summary`` sheet, emit one row per (field, metric).

    ``value_columns`` are the numeric columns to flatten into the long format.
    The ``field_col`` is the descriptor column (e.g. ``Column`` for bert/rouge,
    ``Field`` for entity).
    """
    try:
        df = pd.read_excel(path, sheet_name="Summary", engine="openpyxl")
    except (ValueError, FileNotFoundError):
        return []

    rows = []
    for _, r in df.iterrows():
        field = str(r.get(field_col, "")).strip() or "_overall"
        for col in value_columns:
            if col not in df.columns:
                continue
            value = r[col]
            if pd.isna(value):
                continue
            rows.append(_emit(run, source, field, col, float(value)))
    return rows


def _read_bert(run: RunArtifacts) -> list[dict]:
    path = run.first("bert")
    if path is None:
        return []
    return _read_summary_xlsx(
        path, source="bert", run=run,
        value_columns=("Avg_BERTScore_F1", "Std_BERTScore_F1",
                       "Min_BERTScore_F1", "Max_BERTScore_F1",
                       "Median_BERTScore_F1"),
        field_col="Column",
    )


def _read_rouge(run: RunArtifacts) -> list[dict]:
    path = run.first("rouge")
    if path is None:
        return []
    return _read_summary_xlsx(
        path, source="rouge", run=run,
        value_columns=("Avg_ROUGE_L", "Std_ROUGE_L", "Min_ROUGE_L",
                       "Max_ROUGE_L", "Median_ROUGE_L"),
        field_col="Column",
    )


def _read_entity(run: RunArtifacts) -> list[dict]:
    path = run.first("entity")
    if path is None:
        return []
    return _read_summary_xlsx(
        path, source="entity", run=run,
        value_columns=("Precision", "Recall", "F1_Score"),
        field_col="Field",
    )


def _read_severity(run: RunArtifacts) -> list[dict]:
    """Severity emits a single-row Summary; flatten into ``_overall`` field."""
    path = run.first("severity")
    if path is None:
        return []
    try:
        df = pd.read_excel(path, sheet_name="Summary", engine="openpyxl")
    except (ValueError, FileNotFoundError):
        return []
    rows = []
    for col in ("macro_F1", "accuracy", "n_pairs"):
        if col in df.columns and not df.empty:
            rows.append(_emit(run, "severity", "_overall", col, float(df.iloc[0][col])))
    return rows


def _read_coverage(run: RunArtifacts) -> list[dict]:
    path = run.first("coverage")
    if path is None:
        return []
    rows: list[dict] = []
    try:
        s = pd.read_excel(path, sheet_name="Summary", engine="openpyxl")
        if not s.empty:
            r = s.iloc[0]
            for col in ("exact_record_match", "hallucination_rate", "omission_rate",
                        "n_matched_pairs", "n_extraction_unmatched", "n_baseline_unmatched"):
                if col in s.columns:
                    rows.append(_emit(run, "coverage", "_overall", col, float(r[col])))
    except (ValueError, FileNotFoundError):
        pass
    try:
        pf = pd.read_excel(path, sheet_name="Per_Field", engine="openpyxl")
        for _, r in pf.iterrows():
            rows.append(_emit(run, "coverage", str(r["Field"]),
                              "hallucination_rate", float(r["Hallucination_Rate"])))
            rows.append(_emit(run, "coverage", str(r["Field"]),
                              "omission_rate", float(r["Omission_Rate"])))
    except (ValueError, FileNotFoundError):
        pass
    return rows


def _read_schema(run: RunArtifacts) -> list[dict]:
    path = run.first("schema")
    if path is None:
        return []
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    rows = []
    for col in ("schema_conformance_rate", "type_coercion_rate",
                "extra_fields_rate", "n_records"):
        if col in report:
            rows.append(_emit(run, "schema", "_overall", col, float(report[col])))
    rows.append(_emit(run, "schema", "_overall", "json_valid",
                      1.0 if report.get("json_valid") else 0.0))
    return rows


_READERS = {
    "bert": _read_bert,
    "rouge": _read_rouge,
    "entity": _read_entity,
    "severity": _read_severity,
    "coverage": _read_coverage,
    "schema": _read_schema,
}


# ---------------------------------------------------------------------------
# Top-level aggregation.
# ---------------------------------------------------------------------------

def gather_long(roots: list[Path]) -> pd.DataFrame:
    """Walk all roots and produce the long-format table."""
    all_rows: list[dict] = []
    for root in roots:
        for run in discover_runs(root):
            for reader in _READERS.values():
                all_rows.extend(reader(run))
    if not all_rows:
        return pd.DataFrame(columns=list(_KEY_COLS) + ["value"])
    return pd.DataFrame(all_rows)


def aggregate(long_df: pd.DataFrame) -> pd.DataFrame:
    """Group by everything except ``run`` and compute mean/std/min/max/n."""
    if long_df.empty:
        return long_df.copy()
    group_cols = [c for c in _KEY_COLS if c != "run"]
    g = long_df.groupby(group_cols, dropna=False)["value"]
    return g.agg(["mean", "std", "min", "max", "count"]).reset_index().rename(
        columns={"count": "n_runs"}
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Aggregate per-run metrics across runs.")
    parser.add_argument("--root", type=Path, nargs="+", required=True,
                        help="One or more result roots (e.g. results_runs results_runs_V2)")
    parser.add_argument("--output", type=Path, required=True,
                        help="Output XLSX path")
    args = parser.parse_args()

    long_df = gather_long(args.root)
    if long_df.empty:
        print("[AGG] No artifacts found under the given roots.")
        return

    agg_df = aggregate(long_df)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with pd.ExcelWriter(args.output) as writer:
        agg_df.to_excel(writer, sheet_name="Aggregated", index=False)
        long_df.to_excel(writer, sheet_name="Long", index=False)

    versions = sorted(long_df["version"].unique())
    sources = sorted(long_df["source"].unique())
    print(
        f"[AGG] runs collected: {long_df.groupby(['version','target','model'])['run'].nunique().sum()}"
    )
    print(f"[AGG] versions: {versions}")
    print(f"[AGG] sources : {sources}")
    print(f"[AGG] long rows: {len(long_df)} → aggregated rows: {len(agg_df)}")
    print(f"[AGG] saved → {args.output}")


if __name__ == "__main__":
    main()
