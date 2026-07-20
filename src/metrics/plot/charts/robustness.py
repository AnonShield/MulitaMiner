"""Robustness charts — "can I trust the numbers?" section.

Pure data extraction. Boxplot data = per-run F1 lists; Wilcoxon =
pairwise p-value matrix (Bonferroni-adjusted).
"""
from __future__ import annotations

import math

import numpy as np
import pandas as pd

from metrics.plot.data_source import Dataset


def f1_distribution_box(dataset: Dataset) -> dict:
    """Per-model F1 values across runs, ordered by median desc."""
    df = dataset.long
    f1 = df[(df["source"] == "field_f1") & (df["metric"] == "F1_Score")]
    if f1.empty:
        return {"empty": True, "models": [], "values": {}}

    per_run = f1.groupby(["model", "run"], as_index=False)["value"].mean()
    medians = per_run.groupby("model")["value"].median().sort_values(ascending=False)
    order = medians.index.tolist()
    values = {m: [float(v) for v in per_run[per_run["model"] == m]["value"].tolist()] for m in order}
    return {"empty": False, "models": order, "values": values}


def wilcoxon_pvalue_heatmap(dataset: Dataset, target_metric: str = "F1_Score") -> dict:
    """Pairwise Wilcoxon p-values (Bonferroni-adjusted) as a square matrix.

    NaN cells (no overlap, single value) are encoded as None for JSON.
    """
    df = dataset.long
    f1 = df[(df["source"] == "field_f1") & (df["metric"] == target_metric)]
    if f1.empty:
        return {"empty": True, "models": [], "matrix": [], "reason": "no field_f1 metrics yet"}

    per_run = f1.groupby(["model", "run"], as_index=False)["value"].mean()
    models = sorted(per_run["model"].unique().tolist())
    if len(models) < 2:
        return {"empty": True, "models": models, "matrix": [], "reason": "needs ≥2 models"}

    try:
        from scipy.stats import wilcoxon
    except ImportError:
        return {"empty": True, "models": models, "matrix": [], "reason": "scipy not installed"}

    matrix = pd.DataFrame(index=models, columns=models, dtype=float)
    pvals: list[float] = []
    pairs: list[tuple[str, str]] = []
    for i, a in enumerate(models):
        for b in models[i + 1:]:
            sa = per_run[per_run["model"] == a].set_index("run")["value"]
            sb = per_run[per_run["model"] == b].set_index("run")["value"]
            common = sa.index.intersection(sb.index)
            if len(common) < 2:
                continue
            try:
                _, p = wilcoxon(sa.loc[common].values, sb.loc[common].values)
                pvals.append(float(p))
                pairs.append((a, b))
            except (ValueError, ZeroDivisionError):
                pvals.append(float("nan"))
                pairs.append((a, b))

    valid = sum(1 for p in pvals if not math.isnan(p))
    adjusted = [min(p * valid, 1.0) if not math.isnan(p) else float("nan") for p in pvals]
    for (a, b), p in zip(pairs, adjusted):
        matrix.loc[a, b] = p
        matrix.loc[b, a] = p

    z = matrix.values.astype(float)
    rows = [[None if np.isnan(v) else float(v) for v in row] for row in z]
    return {"empty": False, "models": models, "matrix": rows}
