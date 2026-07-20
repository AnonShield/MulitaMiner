"""Diagnostic charts — "where does it fail?" section."""
from __future__ import annotations

import numpy as np
import pandas as pd

from metrics.plot.data_source import Dataset, load_severity_confusions


def schema_validity_per_model(dataset: Dataset) -> dict:
    """Per-model schema_conformance_rate as percentages — bar chart data.

    Measures LLM compliance with the prompt's own schema (V1/V2/V3 each
    judged by their own contract — the aggregator stores native conformance
    under the canonical ``schema_conformance_rate`` key after the tautological
    canon→V3 view was dropped).
    """
    df = dataset.agg
    sub = df[(df["source"] == "schema") & (df["metric"] == "schema_conformance_rate")]
    if sub.empty:
        return {"empty": True, "models": [], "values": []}
    chosen = sub.groupby("model")["mean"].mean().dropna().sort_values(ascending=False)
    return {
        "empty": chosen.empty,
        "models": chosen.index.tolist(),
        "values": [float(v) * 100 for v in chosen.values],
    }


def json_validity_per_model(dataset: Dataset) -> dict:
    """Per-model JSON validity rate as percentage — bar chart data."""
    df = dataset.agg
    sub = df[(df["source"] == "schema") & (df["metric"] == "json_valid")]
    if sub.empty:
        return {"empty": True, "models": [], "values": []}
    per = sub.groupby("model")["mean"].mean().sort_values(ascending=False)
    return {
        "empty": per.empty,
        "models": per.index.tolist(),
        "values": [float(v) * 100 for v in per.values],
    }


def schema_conformance_heatmap(dataset: Dataset) -> dict:
    """rows=model, cols=field, values=schema_conformance_rate (0..1)."""
    df = dataset.agg
    sub = df[(df["source"] == "schema") & (df["metric"] == "schema_conformance_rate")]
    if sub.empty:
        return {"empty": True, "models": [], "fields": [], "matrix": []}
    pivot = sub.pivot_table(index="model", columns="field", values="mean", aggfunc="mean")
    if pivot.empty:
        return {"empty": True, "models": [], "fields": [], "matrix": []}
    return _pivot_to_dict(pivot)


def severity_confusion_small_multiples(dataset: Dataset) -> dict:
    """One confusion matrix per model: {model: {labels, matrix}}."""
    matrices = load_severity_confusions(dataset.run_dirs)
    if not matrices:
        return {"empty": True, "models": [], "matrices": {}}

    by_model: dict[str, list[pd.DataFrame]] = {}
    for (_target, model), m in matrices.items():
        by_model.setdefault(model, []).append(m)
    averaged = {m: sum(ms) / len(ms) for m, ms in by_model.items()}

    models = sorted(averaged.keys())
    out: dict[str, dict] = {}
    z_max = 0.0
    for m in models:
        mat = averaged[m]
        labels = mat.index.tolist()
        rows = [[float(v) for v in row] for row in mat.values.astype(float)]
        out[m] = {"labels": labels, "matrix": rows}
        z_max = max(z_max, mat.values.max())

    return {"empty": False, "models": models, "matrices": out, "z_max": float(z_max)}


def extra_fields_rate_per_model(dataset: Dataset) -> dict:
    """Per-model rate of records with keys outside the V3 schema.

    Aggregator emits ``extra_fields_rate`` per (model, run) from each
    schema_report; we average across runs. Diagnostic for "is the LLM
    inventing keys the schema doesn't define?".
    """
    df = dataset.agg
    sub = df[(df["source"] == "schema") & (df["metric"] == "extra_fields_rate")]
    if sub.empty:
        return {"empty": True, "models": [], "values": []}
    per = sub.groupby("model")["mean"].mean().sort_values(ascending=False)
    return {
        "empty": per.empty,
        "models": per.index.tolist(),
        "values": [float(v) * 100 for v in per.values],
    }


def missing_fields_top_n(dataset: Dataset, top_n: int = 10) -> dict:
    """Top-N most-missing fields across all runs.

    Aggregates ``missing_field_counts`` from each schema_report.json
    (sums counts across runs and models), then ranks. Diagnostic: which
    schema fields does the LLM most frequently fail to emit?

    Returns ``{rows: [{field, count, models}]}`` — ``models`` is the
    list of distinct models that ever omitted that field, so a high
    count + few models means it's a model-specific gap.
    """
    import json as _json
    from collections import Counter
    if not dataset.run_dirs:
        return {"empty": True, "rows": []}
    total: Counter[str] = Counter()
    by_model: dict[str, set[str]] = {}
    for run_dir in dataset.run_dirs:
        model = run_dir.parent.name
        for path in run_dir.glob("schema_report*.json"):
            try:
                report = _json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            counts = report.get("missing_field_counts") or {}
            for field, n in counts.items():
                total[field] += int(n)
                by_model.setdefault(field, set()).add(model)
    if not total:
        return {"empty": True, "rows": []}
    rows = []
    for field, cnt in total.most_common(top_n):
        rows.append({
            "field": field,
            "count": int(cnt),
            "models": sorted(by_model.get(field, [])),
            "n_models": len(by_model.get(field, [])),
        })
    return {"empty": False, "rows": rows}


def field_hallucination_omission_heatmap(dataset: Dataset, kind: str = "hallucination_rate") -> dict:
    """Per-(model, field) heatmap of hallucination_rate or omission_rate.

    Diagnostic complement to ``field_coverage_heatmap`` — instead of "how
    well does the LLM score on this field when it answers?", this asks
    "on which fields does the LLM most invent (hallucinate) or skip
    (omit) content?". Values are fractions in [0, 1].

    Args:
        kind: ``"hallucination_rate"`` or ``"omission_rate"``.
    """
    df = dataset.agg
    sub = df[(df["source"] == "coverage") & (df["metric"] == kind) & (df["field"] != "_overall")]
    if sub.empty:
        return {"empty": True, "fields": [], "models": [], "matrix": [], "kind": kind}
    pivot = sub.pivot_table(index="field", columns="model", values="mean", aggfunc="mean")
    pivot = pivot.dropna(axis=0, how="all")
    if pivot.empty:
        return {"empty": True, "fields": [], "models": [], "matrix": [], "kind": kind}
    # Order fields by overall mean — worst at bottom (the failure surface).
    pivot = pivot.loc[pivot.mean(axis=1).sort_values(ascending=True).index]
    d = _pivot_to_dict(pivot)
    return {
        "empty": False,
        "fields": d["models"],   # rows = field
        "models": d["fields"],   # cols = model
        "matrix": d["matrix"],
        "kind": kind,
    }


def field_coverage_heatmap(dataset: Dataset, metric: str = "F1_Score") -> dict:
    """rows=field, cols=model, values=metric mean. Fields ordered by mean desc."""
    df = dataset.agg
    sub = df[(df["source"] == "field_f1") & (df["metric"] == metric)]
    if sub.empty:
        return {"empty": True, "fields": [], "models": [], "matrix": []}
    pivot = sub.pivot_table(index="field", columns="model", values="mean", aggfunc="mean")
    pivot = pivot.dropna(axis=0, how="all")
    if pivot.empty:
        return {"empty": True, "fields": [], "models": [], "matrix": []}
    pivot = pivot.loc[pivot.mean(axis=1).sort_values(ascending=False).index]
    d = _pivot_to_dict(pivot)
    # Rename keys to match field-coverage semantics (rows=field, cols=model).
    return {
        "empty": False,
        "fields": d["models"],
        "models": d["fields"],
        "matrix": d["matrix"],
        "metric": metric,
    }


def _pivot_to_dict(pivot: pd.DataFrame) -> dict:
    """Encode a DataFrame as {models: rows, fields: cols, matrix: 2D list with None for NaN}."""
    z = pivot.values.astype(float)
    matrix = [[None if np.isnan(v) else float(v) for v in row] for row in z]
    return {
        "empty": False,
        "models": [str(x) for x in pivot.index.tolist()],
        "fields": [str(x) for x in pivot.columns.tolist()],
        "matrix": matrix,
    }
