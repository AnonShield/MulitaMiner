"""Versioning charts (§0) — pipeline-version comparison.

Paper-only: surfaced as PNG exports, not embedded in the HTML report.
Version names come straight from ``dataset.versions`` (the aggregator's
verbatim folder basenames, e.g. ``results_runs``, ``results_runs_v2``);
no hardcoded ``V2``/``V3`` labels — everything sorts naturally.
"""
from __future__ import annotations

import json
from typing import Iterable

from metrics.plot.data_source import Dataset


_HEADLINE_METRICS = [
    # F1 (per-match) was dropped from the headline — it's the conditional
    # half of F1 (coverage-aware), already visible as the Y axis of the
    # Recall × F1 scatter. Keeping it as a KPI/leaderboard column added
    # noise: leaders kept reading −Δ as "regression" when the coverage-aware
    # number was actually up. The scatter is the right place to decompose.
    ("severity", "coverage_aware_macro_F1",           "Severity Macro-F1 (coverage-aware)", False),
    ("coverage", "exact_record_match",                "Exact Record Match",       True),
    # ``schema_field_conformance_rate_native`` — per-field LLM compliance
    # against the version's own schema. Soft metric: averages pass-rate across
    # all field-checks instead of demanding every field on every record. A
    # single recurrent type error (e.g. V2 plugin_details emitted as list)
    # doesn't collapse it to 0%. The "auto/legacy" rate was dropped from the
    # headline — it's mostly canonicalised-clean (residual ~0), so the KPI
    # carried no signal. Coercion cost lives in the Type-coercion breakdown
    # chart instead.
    ("schema",   "schema_field_conformance_rate_native", "Schema (per-field LLM compliance)", True),
]


def _versions(dataset: Dataset) -> list[str]:
    """All versions the agg has data for, in CLI/load order (baseline first)."""
    return list(dataset.versions or [])


def headline_per_version(dataset: Dataset) -> dict:
    """Mean of headline metrics per (version, model). Skips empty metric blocks."""
    df = dataset.agg
    versions = _versions(dataset)
    if df.empty or not versions:
        return {"empty": True, "versions": [], "models": [], "metrics": []}

    models = sorted({m for m in df["model"].dropna().unique()})
    blocks = []
    for source, metric_key, label, is_pct in _HEADLINE_METRICS:
        sub = df[(df["source"] == source) & (df["metric"] == metric_key)]
        if sub.empty:
            continue
        per_version: dict[str, list[float | None]] = {}
        for v in versions:
            agg = sub[sub["version"] == v].groupby("model")["mean"].mean()
            per_version[v] = [
                (float(agg[m]) * (100 if is_pct else 1)) if m in agg.index else None
                for m in models
            ]
        if any(any(x is not None for x in vals) for vals in per_version.values()):
            blocks.append({"label": label, "is_pct": is_pct, "values": per_version})

    if not blocks:
        return {"empty": True, "versions": versions, "models": models, "metrics": []}
    return {"empty": False, "versions": versions, "models": models, "metrics": blocks}


def similarity_distribution_per_version(dataset: Dataset) -> dict:
    """Stacked similarity buckets per (version, model), BERT and ROUGE.

    Aggregates ``Categorization`` counts across **all baselines and runs**
    of each (version, model), then converts to percentages. ``Non-existent``
    is excluded from the denominator (LLM invention, not a similarity score).

    Output shape::

        {
          "versions": [...],          # ordered, e.g. ["results_runs_v2", "results_runs_v3"]
          "models":   [...],
          "categories": ["Highly Similar", ..., "Absent"],
          "bert":  {version: {model: [%hs, %ms, %ss, %div, %abs]}},
          "rouge": {version: {model: [%hs, %ms, %ss, %div, %abs]}},
        }
    """
    import pandas as pd

    categories = ["Highly Similar", "Moderately Similar", "Slightly Similar",
                  "Divergent", "Absent"]
    metric_files = {"bert": "bert_comparison", "rouge": "rouge_comparison"}

    versions = _versions(dataset)
    if not versions or not dataset.run_dirs:
        return {"empty": True, "versions": [], "models": [], "categories": categories,
                "bert": {}, "rouge": {}}

    # raw[metric][version][model] = [counts_per_category]
    raw: dict[str, dict[str, dict[str, list[int]]]] = {
        m: {v: {} for v in versions} for m in metric_files
    }

    for run_dir in dataset.run_dirs:
        v = _detect_version(run_dir, versions)
        if v is None:
            continue
        model = run_dir.parent.name
        for metric, prefix in metric_files.items():
            for path in run_dir.glob(f"{prefix}_*.xlsx"):
                try:
                    df = pd.read_excel(path, sheet_name="Categorization")
                except (ValueError, FileNotFoundError):
                    continue
                if "Category" not in df.columns:
                    continue
                bucket = raw[metric][v].setdefault(model, [0] * len(categories))
                for i, cat in enumerate(categories):
                    bucket[i] += int((df["Category"] == cat).sum())

    models = sorted({m for metric in raw.values() for v in metric.values() for m in v.keys()})
    if not models:
        return {"empty": True, "versions": versions, "models": [], "categories": categories,
                "bert": {}, "rouge": {}}

    def to_pct(metric_key: str) -> dict[str, dict[str, list[float]]]:
        out: dict[str, dict[str, list[float]]] = {}
        for v in versions:
            out[v] = {}
            for m in models:
                counts = raw[metric_key][v].get(m, [0] * len(categories))
                total = sum(counts)
                out[v][m] = [round((c / total) * 100, 2) if total else 0.0 for c in counts]
        return out

    bert, rouge = to_pct("bert"), to_pct("rouge")
    has_data = any(any(any(x > 0 for x in vals) for vals in d[v].values())
                   for d in (bert, rouge) for v in versions)
    if not has_data:
        return {"empty": True, "versions": versions, "models": [], "categories": categories,
                "bert": {}, "rouge": {}}

    return {"empty": False, "versions": versions, "models": models,
            "categories": categories, "bert": bert, "rouge": rouge}


def json_validity_per_version(dataset: Dataset) -> dict:
    """Mean of ``json_valid`` (0/1) per (version, model), as percentage."""
    df = dataset.agg
    sub = df[(df["source"] == "schema") & (df["metric"] == "json_valid")]
    versions = _versions(dataset)
    if sub.empty or not versions:
        return {"empty": True, "versions": [], "models": [], "values": {}}

    models = sorted({m for m in sub["model"].dropna().unique()})
    out: dict[str, list[float | None]] = {}
    any_data = False
    for v in versions:
        agg = sub[sub["version"] == v].groupby("model")["mean"].mean()
        row = [(float(agg[m]) * 100) if m in agg.index else None for m in models]
        if any(x is not None for x in row):
            any_data = True
        out[v] = row
    if not any_data:
        return {"empty": True, "versions": versions, "models": models, "values": {}}
    return {"empty": False, "versions": versions, "models": models, "values": out}


def _detect_version(run_dir, known_versions: Iterable[str]) -> str | None:
    """Find which known version a run_dir belongs to by walking its parents."""
    names = {n for n in known_versions}
    for ancestor in (run_dir, *run_dir.parents):
        if ancestor.name in names:
            return ancestor.name
    return None
