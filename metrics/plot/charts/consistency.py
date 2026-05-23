"""Model consistency — derived from per-run F1 variance.

For each model, compute the std and coefficient of variation (CV = std/mean)
of F1_Score across runs. Lower CV = more consistent across runs of the
same target. Returned as a sortable table (rows = models).
"""
from __future__ import annotations

from metrics.plot.data_source import Dataset


def consistency_table(dataset: Dataset) -> list[dict]:
    """One row per model with mean F1, std F1, CV, and a qualitative band."""
    df = dataset.long
    if df.empty:
        return []

    f1 = df[(df["source"] == "entity") & (df["metric"] == "F1_Score")]
    if f1.empty:
        return []

    # Average fields/targets per (model, run) so each row is one F1 score per run.
    per_run = f1.groupby(["model", "run"], as_index=False)["value"].mean()
    if per_run.empty:
        return []

    rows = []
    for m, sub in per_run.groupby("model"):
        vals = sub["value"].astype(float)
        if len(vals) < 1:
            continue
        mean = float(vals.mean())
        std = float(vals.std(ddof=0)) if len(vals) > 1 else 0.0
        cv = (std / mean) if mean > 0 else 0.0
        rows.append({
            "model": str(m), "n_runs": int(len(vals)),
            "mean": mean, "std": std, "cv": cv,
            "mean_str": f"{mean:.4f}", "std_str": f"{std:.4f}", "cv_str": f"{cv*100:.2f}%",
            "band": _band(cv),
        })
    rows.sort(key=lambda r: r["cv"])
    return rows


def _band(cv: float) -> str:
    """Qualitative consistency label. Thresholds chosen to match small-N
    LLM-eval norms: <2% CV is run-to-run noise, >10% is unstable."""
    if cv < 0.02:
        return "very stable"
    if cv < 0.05:
        return "stable"
    if cv < 0.10:
        return "moderate"
    return "unstable"
