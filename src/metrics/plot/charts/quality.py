"""Quality charts — "which model is best?" section.

Pure data extraction: every function returns a JSON-serializable dict.
Rendering lives in ``report.py`` (Chart.js via Jinja) and ``png.py``
(matplotlib for paper figures). One source of data, two renderers.
"""
from __future__ import annotations

from metrics.plot.data_source import Dataset


def precision_recall_f1(dataset: Dataset) -> dict:
    """Mean ± σ of P/R/F1 per model, ordered by F1 desc."""
    df = dataset.agg
    sub = df[(df["source"] == "field_f1") & (df["metric"].isin(["Precision", "Recall", "F1_Score"]))]
    if sub.empty:
        return {"empty": True, "models": [], "values": {}, "stds": {}}

    grouped = sub.groupby(["model", "metric"], as_index=False).agg(
        mean=("mean", "mean"), std=("mean", "std"),
    )
    f1_order = (
        grouped[grouped["metric"] == "F1_Score"]
        .sort_values("mean", ascending=False)["model"].tolist()
    )
    if not f1_order:
        f1_order = sorted(grouped["model"].unique().tolist())

    keys = {"Precision": "Precision", "Recall": "Recall", "F1_Score": "F1"}
    values: dict[str, list[float]] = {}
    stds: dict[str, list[float]] = {}
    for src_key, label in keys.items():
        rows = grouped[grouped["metric"] == src_key].set_index("model").reindex(f1_order)
        values[label] = [float(v) if v == v else 0.0 for v in rows["mean"].fillna(0).tolist()]
        stds[label] = [float(v) if v == v else 0.0 for v in rows["std"].fillna(0).tolist()]

    return {"empty": False, "models": f1_order, "values": values, "stds": stds}


def recall_vs_f1_scatter(dataset: Dataset) -> dict:
    """Per-model (recall, per-match F1, effective F1) for the Quality scatter.

    The single-version twin of ``comparison.recall_vs_f1_scatter`` —
    drops the version dimension (every model has one point). Lets the
    Quality view show the trade-off intra-version with iso-Effective-F1
    contours, so readers see *why* Effective F1 ranks models the way it
    does (a model can win on Effective F1 by trading per-match F1 for
    coverage and vice-versa).
    """
    df = dataset.agg
    if df.empty:
        return {"empty": True, "points": []}

    f1 = df[(df["source"] == "field_f1") & (df["metric"] == "F1_Score")]
    om = df[(df["source"] == "coverage") & (df["metric"] == "omission_rate")]
    if f1.empty or om.empty:
        return {"empty": True, "points": [], "reason": "need field_f1 + coverage omission_rate"}

    f1_per = f1.groupby("model")["mean"].mean()
    om_per = om.groupby("model")["mean"].mean()
    points = []
    for m in f1_per.index.intersection(om_per.index):
        recall = float(1 - om_per[m])
        per_f1 = float(f1_per[m])
        points.append({
            "model": str(m),
            "recall": recall, "f1": per_f1,
            "effective": recall * per_f1,
        })
    if not points:
        return {"empty": True, "points": []}
    return {"empty": False, "points": points}


def hallucination_omission_scatter(dataset: Dataset) -> dict:
    """One point per model: (hallucination_rate, omission_rate, n_runs)."""
    df = dataset.agg
    halluc = df[(df["source"] == "coverage") & (df["metric"] == "hallucination_rate")]
    omiss = df[(df["source"] == "coverage") & (df["metric"] == "omission_rate")]
    if halluc.empty or omiss.empty:
        return {"empty": True, "points": []}

    halluc = halluc.groupby("model", as_index=False).agg(
        halluc_mean=("mean", "mean"), n=("n_runs", "max"),
    )
    omiss = omiss.groupby("model", as_index=False).agg(omiss_mean=("mean", "mean"))
    merged = halluc.merge(omiss, on="model", how="inner")
    if merged.empty:
        return {"empty": True, "points": []}

    points = [
        {
            "model": str(row["model"]),
            "halluc": float(row["halluc_mean"]),
            "omiss": float(row["omiss_mean"]),
            "n": int(row["n"]) if row["n"] == row["n"] else 1,
        }
        for _, row in merged.iterrows()
    ]
    return {"empty": False, "points": points}
