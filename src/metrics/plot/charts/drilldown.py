"""Drill-down charts — exploratory section.

Per-field BERT vs ROUGE comparison across models.
"""
from __future__ import annotations

from metrics.plot.data_source import Dataset, load_similarity_categorizations


_TEXT_SCORERS = [
    ("bert",     "Avg_BERTScore_F1"),
    ("rouge",    "Avg_ROUGE_L"),
    ("token_f1", "Avg_Token_F1"),
]


_ALL_BASELINES = "__all__"


def text_similarity_by_field(dataset: Dataset) -> dict:
    """Per-(baseline, scorer, model, field) heatmap data — three text scorers.

    Returns matrices grouped by baseline; the special ``__all__`` key is
    the mean across every baseline (the original "global" view). UI puts
    a selector above the heatmaps so the reader can switch between the
    aggregate and a specific baseline. Scorers absent from the agg are
    dropped from ``available``.

    Field ordering is computed once from the ``__all__`` view so column
    positions stay stable when the user switches baselines (no jarring
    re-shuffle on selection change).
    """
    df = dataset.agg
    sub = df[df["source"].isin([s for s, _ in _TEXT_SCORERS])]
    sub = sub[sub["metric"].isin([m for _, m in _TEXT_SCORERS])]
    if sub.empty:
        return {"empty": True, "models": [], "fields": [], "available": [],
                "baselines": [], "matrices": {}}

    models = sorted(sub["model"].dropna().unique().tolist())
    all_fields = [f for f in sorted(sub["field"].dropna().unique().tolist())
                  if f and f != "_overall"]
    targets = sorted(sub["target"].dropna().unique().tolist())
    if not models or not all_fields:
        return {"empty": True, "models": [], "fields": [], "available": [],
                "baselines": [], "matrices": {}}

    def build_matrix(rows_df, source: str, metric_key: str) -> list[list[float | None]]:
        rows = []
        for m in models:
            row = []
            for f in all_fields:
                cell = rows_df[(rows_df["source"] == source) & (rows_df["model"] == m) &
                               (rows_df["field"] == f) & (rows_df["metric"] == metric_key)]
                if cell.empty:
                    row.append(None)
                else:
                    v = float(cell["mean"].mean())
                    row.append(v if v == v else None)
            rows.append(row)
        return rows

    available = [s for s, _ in _TEXT_SCORERS if (sub["source"] == s).any()]
    if not available:
        return {"empty": True, "models": [], "fields": [], "available": [],
                "baselines": [], "matrices": {}}

    def matrices_for(rows_df) -> dict[str, list[list[float | None]]]:
        return {s: build_matrix(rows_df, s, mk) for s, mk in _TEXT_SCORERS if s in available}

    per_baseline: dict[str, dict[str, list[list[float | None]]]] = {
        _ALL_BASELINES: matrices_for(sub),
    }
    for t in targets:
        per_baseline[t] = matrices_for(sub[sub["target"] == t])

    # Field ordering — computed from the global view so columns don't reshuffle
    # when the user switches baselines.
    all_matrices = per_baseline[_ALL_BASELINES]
    def field_score(j):
        vals = [r[j] for mat in all_matrices.values() for r in mat if r[j] is not None]
        return -(sum(vals) / len(vals)) if vals else 0
    order = sorted(range(len(all_fields)), key=field_score)
    fields = [all_fields[i] for i in order]
    per_baseline = {
        b: {k: [[r[i] for i in order] for r in mat] for k, mat in mats.items()}
        for b, mats in per_baseline.items()
    }

    return {
        "empty": False,
        "models": models,
        "fields": fields,
        "available": available,
        "baselines": [_ALL_BASELINES, *targets],
        "matrices": per_baseline,
    }


def similarity_distribution(dataset: Dataset) -> dict:
    """Stacked similarity buckets per (baseline, model), BERT and ROUGE.

    Percentages sum to 100 within each (metric, baseline, model). Same
    palette/grouping as the legacy report: x-axis groups by model, each
    group has one stacked bar per baseline (legacy used hatches; HTML/PNG
    consumers map baseline → distinguishable visual). ``Non-existent`` is
    excluded — it isn't a similarity score.
    """
    categories = ["Highly Similar", "Moderately Similar", "Slightly Similar", "Divergent", "Absent"]
    raw = load_similarity_categorizations(dataset.run_dirs)
    if not raw:
        return {"empty": True, "models": [], "baselines": [], "categories": categories, "bert": {}, "rouge": {}}

    baselines = sorted({b for metric in raw.values() for b in metric.keys()})
    models = sorted({m for metric in raw.values() for b in metric.values() for m in b.keys()})

    def to_pct(metric_key: str) -> dict[str, dict[str, list[float]]]:
        out: dict[str, dict[str, list[float]]] = {}
        per_baseline = raw.get(metric_key, {})
        for b in baselines:
            per_model = per_baseline.get(b, {})
            out[b] = {}
            for m in models:
                counts = per_model.get(m, [0] * len(categories))
                total = sum(counts)
                out[b][m] = [round((c / total) * 100, 2) if total else 0.0 for c in counts]
        return out

    bert, rouge = to_pct("bert"), to_pct("rouge")
    has_data = any(sum(v) > 0 for b in bert.values() for v in b.values()) or \
               any(sum(v) > 0 for b in rouge.values() for v in b.values())
    if not has_data:
        return {"empty": True, "models": [], "baselines": [], "categories": categories, "bert": {}, "rouge": {}}

    return {
        "empty": False,
        "models": models,
        "baselines": baselines,
        "categories": categories,
        "bert": bert,
        "rouge": rouge,
    }
