"""Data extractors for the multi-version (V2 vs V3) HTML comparison report.

Reuses :mod:`metrics.plot.charts.versioning` for chart data already shaped
per-version (headline metrics, type-coercion, JSON validity, similarity);
adds the comparison-specific aggregations on top:

  * :func:`headline_kpis_with_delta` — 4 KPIs × N versions, with delta vs baseline version.
  * :func:`leaderboard_wide`         — wide model × (metric, version, delta) table.
  * :func:`wilcoxon_pairs`           — paired Wilcoxon between every version-pair, per (model, metric).
  * :func:`similarity_per_baseline_per_version` — drill-down: similarity per baseline × version.
"""
from __future__ import annotations

import math

import pandas as pd

from metrics.plot.data_source import Dataset
from metrics.plot.charts.versioning import _HEADLINE_METRICS, _versions, _detect_version
from metrics.plot.charts.kpi import effective_f1_per_model


# Synthetic metric: Effective F1 = (1 − omission_rate) × per_match_F1.
# Treated as a first-class headline alongside the entity/severity/coverage
# scalars. Marker source/metric_key so downstream code can dispatch off them.
_EFFECTIVE_F1 = ("__derived__", "effective_f1", "F1 (coverage-aware)", False)


def headline_kpis_with_delta(dataset: Dataset) -> dict:
    """4 headline metrics aggregated per version (mean across models).

    Returns one block per metric with values for each version and the
    delta of every non-baseline version vs the first version (alphabetical).
    """
    df = dataset.agg
    versions = _versions(dataset)
    if df.empty or not versions:
        return {"empty": True, "versions": [], "metrics": []}

    blocks: list[dict] = []
    metric_specs = [_EFFECTIVE_F1, *_HEADLINE_METRICS]
    for source, metric_key, label, is_pct in metric_specs:
        per_version = {}
        if source == "__derived__" and metric_key == "effective_f1":
            for v in versions:
                eff = effective_f1_per_model(dataset, version=v)
                if eff:
                    per_version[v] = sum(eff.values()) / len(eff)
        else:
            sub = df[(df["source"] == source) & (df["metric"] == metric_key)]
            if sub.empty:
                continue
            for v in versions:
                vsub = sub[sub["version"] == v]
                if vsub.empty:
                    continue
                mean = float(vsub.groupby("model")["mean"].mean().mean())
                per_version[v] = mean * (100 if is_pct else 1)
        if not per_version:
            continue
        baseline_v = versions[0]
        baseline_val = per_version.get(baseline_v)
        deltas = {}
        if baseline_val is not None:
            for v, val in per_version.items():
                if v == baseline_v:
                    continue
                deltas[v] = val - baseline_val
        blocks.append({
            "label": label, "is_pct": is_pct, "source": source, "metric": metric_key,
            "values": per_version, "deltas": deltas, "baseline_version": baseline_v,
        })
    if not blocks:
        return {"empty": True, "versions": versions, "metrics": []}
    return {"empty": False, "versions": versions, "metrics": blocks}


def leaderboard_wide(dataset: Dataset) -> dict:
    """Wide model × (metric, version, delta) table.

    Output::

        {
          "versions": [...],
          "metrics":  [{label, is_pct, source, metric_key}, ...],
          "models":   [...],
          "cells":    {model: {metric_key: {version: float | None, "delta": float | None}}},
        }

    Delta is computed against the first version (alphabetical) per metric.
    Models sorted by F1 on the last version (canonical/best — V3 first).
    """
    df = dataset.agg
    versions = _versions(dataset)
    if df.empty or not versions:
        return {"empty": True, "versions": [], "metrics": [], "models": [], "cells": {}}

    metric_specs = [
        {"label": label, "is_pct": is_pct, "source": source, "metric_key": metric_key}
        for source, metric_key, label, is_pct in [_EFFECTIVE_F1, *_HEADLINE_METRICS]
        if (source == "__derived__"
            or not df[(df["source"] == source) & (df["metric"] == metric_key)].empty)
    ]
    if not metric_specs:
        return {"empty": True, "versions": versions, "metrics": [], "models": [], "cells": {}}

    models = sorted({m for m in df["model"].dropna().unique()})
    baseline_v = versions[0]
    canonical_v = versions[-1]  # last alphabetically — usually V3 / canonical

    # Pre-compute Effective F1 per (version, model) once.
    eff_per_v = {v: effective_f1_per_model(dataset, version=v) for v in versions}

    cells: dict[str, dict[str, dict]] = {m: {} for m in models}
    for spec in metric_specs:
        is_derived = spec["source"] == "__derived__"
        if not is_derived:
            sub = df[(df["source"] == spec["source"]) & (df["metric"] == spec["metric_key"])]
        for m in models:
            row: dict[str, float | None] = {}
            for v in versions:
                if is_derived and spec["metric_key"] == "effective_f1":
                    val = eff_per_v[v].get(m)
                    row[v] = val
                else:
                    vsub = sub[(sub["version"] == v) & (sub["model"] == m)]
                    row[v] = (float(vsub["mean"].mean()) * (100 if spec["is_pct"] else 1)) if not vsub.empty else None
            base, canon = row.get(baseline_v), row.get(canonical_v)
            row["delta"] = (canon - base) if (base is not None and canon is not None) else None
            cells[m][spec["metric_key"]] = row

    # Sort models by canonical-version Effective F1 desc.
    canon_eff = eff_per_v.get(canonical_v, {})
    if canon_eff:
        ranked = sorted(canon_eff.items(), key=lambda kv: -kv[1])
        models = [m for m, _ in ranked if m in models] + [m for m in models if m not in canon_eff]

    return {
        "empty": False, "versions": versions, "metrics": metric_specs,
        "models": models, "cells": cells, "baseline_version": baseline_v,
        "canonical_version": canonical_v,
    }


def wilcoxon_pairs(dataset: Dataset) -> dict:
    """Paired Wilcoxon V2 vs V3 per (model) on F1_Score.

    Pairing: per (target, run) — the same baseline + run number under each
    version is the matched sample. Bonferroni-adjusted across the model
    family. Returns ``{models, p_values, significant}`` where
    ``significant[m] = True`` iff p < 0.05 after correction.
    """
    df = dataset.long
    versions = _versions(dataset)
    if df.empty or len(versions) < 2:
        return {"empty": True, "models": [], "p_values": {}, "significant": {},
                "versions": versions}

    f1 = df[(df["source"] == "entity") & (df["metric"] == "F1_Score")]
    if f1.empty:
        return {"empty": True, "models": [], "p_values": {}, "significant": {},
                "versions": versions, "reason": "no entity F1 rows"}

    try:
        from scipy.stats import wilcoxon
    except ImportError:
        return {"empty": True, "models": [], "p_values": {}, "significant": {},
                "versions": versions, "reason": "scipy not installed"}

    # We compare the first version against the last (alphabetical). For 2 versions
    # this is V2 vs V3; for 3+ versions the chart still makes sense as "baseline
    # vs latest".
    v_a, v_b = versions[0], versions[-1]

    # Average across fields per (version, target, model, run) so each run is one F1.
    per_run = f1.groupby(["version", "target", "model", "run"], as_index=False)["value"].mean()
    pivot = per_run.pivot_table(
        index=["target", "model", "run"], columns="version", values="value",
    )
    if v_a not in pivot.columns or v_b not in pivot.columns:
        return {"empty": True, "models": [], "p_values": {}, "significant": {},
                "versions": versions, "reason": f"need both versions ({v_a}, {v_b})"}

    paired = pivot[[v_a, v_b]].dropna()
    if paired.empty:
        return {"empty": True, "models": [], "p_values": {}, "significant": {},
                "versions": versions, "reason": "no paired (target,run) under both versions"}

    p_values: dict[str, float] = {}
    raw_pairs: list[tuple[str, float]] = []
    for model, sub in paired.reset_index().groupby("model"):
        if len(sub) < 2:
            p_values[model] = float("nan")
            continue
        try:
            _, p = wilcoxon(sub[v_a].values, sub[v_b].values)
            p_values[model] = float(p)
            raw_pairs.append((model, float(p)))
        except (ValueError, ZeroDivisionError):
            p_values[model] = float("nan")

    # Bonferroni — adjust across the family of valid tests.
    valid = sum(1 for _, p in raw_pairs if not math.isnan(p))
    adjusted = {m: (min(p * valid, 1.0) if (valid and not math.isnan(p)) else float("nan"))
                for m, p in p_values.items()}

    models = sorted(adjusted.keys())

    # Direction (which version is better). Positive => v_b > v_a.
    direction = {}
    for model in models:
        sub = paired.reset_index()
        sub = sub[sub["model"] == model]
        if not sub.empty:
            diff = float(sub[v_b].mean() - sub[v_a].mean())
            direction[model] = diff
        else:
            direction[model] = 0.0

    return {
        "empty": False,
        "models": models,
        "versions": [v_a, v_b],
        "p_values": {m: (None if math.isnan(p) else round(p, 4)) for m, p in adjusted.items()},
        "significant": {m: (p < 0.05) for m, p in adjusted.items() if not math.isnan(p)},
        "direction": {m: round(d, 4) for m, d in direction.items()},
    }


def recall_vs_f1_scatter(dataset: Dataset) -> dict:
    """Per-(version, model) (recall, per-match F1) coordinates for the scatter.

    Recall = 1 − omission_rate. F1 = entity F1_Score (conditioned on match).
    The chart draws each (model, version) as a point and connects same-model
    points across versions with an arrow — visualising the Pareto move
    (V2→V3 typically: ↑ recall, ↓ F1, net ↗ effective).
    """
    df = dataset.agg
    versions = _versions(dataset)
    if df.empty or not versions:
        return {"empty": True, "versions": [], "points": []}

    f1 = df[(df["source"] == "entity") & (df["metric"] == "F1_Score")]
    om = df[(df["source"] == "coverage") & (df["metric"] == "omission_rate")]
    if f1.empty or om.empty:
        return {"empty": True, "versions": versions, "points": [],
                "reason": "need entity F1 + coverage omission_rate"}

    points = []
    for v in versions:
        f1v = f1[f1["version"] == v].groupby("model")["mean"].mean()
        omv = om[om["version"] == v].groupby("model")["mean"].mean()
        for m in f1v.index.intersection(omv.index):
            recall = float(1 - omv[m])
            per_f1 = float(f1v[m])
            points.append({
                "version": v, "model": m,
                "recall": recall, "f1": per_f1,
                "effective": recall * per_f1,
            })
    if not points:
        return {"empty": True, "versions": versions, "points": []}
    return {"empty": False, "versions": versions, "points": points}


def cv_per_version(dataset: Dataset) -> dict:
    """Per-(version, model) coefficient of variation of F1 across runs.

    CV = σ / μ. Lower = more reproducible. Δ CV between versions answers:
    "did the new pipeline make the LLM behave more consistently across
    runs?" Negative Δ = improvement (less variance), positive Δ = regression.

    Returns ``{versions, models, cv: {version: {model: float}}, delta: {model: float}}``.
    """
    df = dataset.long
    versions = _versions(dataset)
    if df.empty or len(versions) < 2:
        return {"empty": True, "versions": [], "models": [], "cv": {}, "delta": {}}

    f1 = df[(df["source"] == "entity") & (df["metric"] == "F1_Score")]
    if f1.empty:
        return {"empty": True, "versions": versions, "models": [], "cv": {}, "delta": {},
                "reason": "no entity F1 rows"}

    # Average across fields/targets per (version, model, run) — one F1 score per run.
    per_run = f1.groupby(["version", "model", "run"], as_index=False)["value"].mean()

    cv: dict[str, dict[str, float]] = {v: {} for v in versions}
    for v in versions:
        sub = per_run[per_run["version"] == v]
        for model, group in sub.groupby("model"):
            vals = group["value"].astype(float)
            if len(vals) < 2:
                continue
            mean = float(vals.mean())
            std = float(vals.std(ddof=0))
            cv[v][str(model)] = (std / mean) if mean > 0 else 0.0

    models = sorted({m for vmap in cv.values() for m in vmap.keys()})
    if not models:
        return {"empty": True, "versions": versions, "models": [], "cv": {}, "delta": {}}

    v_a, v_b = versions[0], versions[-1]  # baseline → canonical
    delta = {}
    for m in models:
        a = cv.get(v_a, {}).get(m)
        b = cv.get(v_b, {}).get(m)
        if a is not None and b is not None:
            delta[m] = b - a  # negative = canonical more stable
    return {
        "empty": False,
        "versions": versions, "models": models,
        "cv": cv, "delta": delta,
        "baseline_version": v_a, "canonical_version": v_b,
    }


def schema_field_failures_per_version(dataset: Dataset) -> dict:
    """Per-field failure rates per (version, model) from ``schema_report*.json``.

    Reads each run's ``field_failure_counts`` and divides by
    ``n_records`` to get a per-field, per-record failure rate. Summed across
    runs of the same (version, model). The result is the *transparency layer*
    behind the per-field conformance KPI — answers "which field is dragging
    the score down?".

    Returns ``{versions, fields, models, rates: {version: {model: {field: rate}}}}``.
    """
    import json as _json

    versions = _versions(dataset)
    if not versions or not dataset.run_dirs:
        return {"empty": True, "versions": [], "fields": [], "models": [], "rates": {}}

    # raw[version][model][field] = (sum_failures, sum_records)
    raw: dict[str, dict[str, dict[str, list[int]]]] = {v: {} for v in versions}
    for run_dir in dataset.run_dirs:
        v = _detect_version(run_dir, versions)
        if v is None:
            continue
        model = run_dir.parent.name
        for path in run_dir.glob("schema_report*.json"):
            try:
                report = _json.loads(path.read_text(encoding="utf-8"))
            except (_json.JSONDecodeError, OSError):
                continue
            failures = report.get("field_failure_counts") or {}
            n_rec = int(report.get("n_records") or 0)
            if not failures or n_rec <= 0:
                continue
            bucket = raw[v].setdefault(model, {})
            for field, n in failures.items():
                acc = bucket.setdefault(field, [0, 0])
                acc[0] += int(n)
                acc[1] += n_rec

    models = sorted({m for vmap in raw.values() for m in vmap.keys()})
    fields = sorted({f for vmap in raw.values() for mmap in vmap.values()
                     for f in mmap.keys()})
    if not models or not fields:
        return {"empty": True, "versions": versions, "fields": [], "models": [],
                "rates": {}}

    rates: dict[str, dict[str, dict[str, float]]] = {}
    for v in versions:
        rates[v] = {}
        for m in models:
            row = {}
            for f in fields:
                fail, total = raw[v].get(m, {}).get(f, [0, 0])
                row[f] = (fail / total) if total else 0.0
            rates[v][m] = row

    # Order fields by worst average failure rate across (version, model) for
    # readability — biggest offenders first.
    def avg_rate(f):
        vals = [rates[v][m][f] for v in versions for m in models]
        return -sum(vals) / max(1, len(vals))
    fields = sorted(fields, key=avg_rate)

    return {"empty": False, "versions": versions, "fields": fields,
            "models": models, "rates": rates}


def similarity_per_baseline_per_version(dataset: Dataset) -> dict:
    """Per-baseline similarity stacks, one per version.

    Drill-down for the comparison report: select a baseline + see V2 vs V3
    side by side for BERT and ROUGE.
    """
    categories = ["Highly Similar", "Moderately Similar", "Slightly Similar",
                  "Divergent", "Absent"]
    metric_files = {"bert": "bert_comparison", "rouge": "rouge_comparison"}
    versions = _versions(dataset)
    if not versions or not dataset.run_dirs:
        return {"empty": True, "versions": [], "baselines": [], "models": [],
                "categories": categories, "bert": {}, "rouge": {}}

    # raw[metric][version][baseline][model] = [counts]
    raw: dict[str, dict[str, dict[str, dict[str, list[int]]]]] = {
        m: {v: {} for v in versions} for m in metric_files
    }
    for run_dir in dataset.run_dirs:
        v = _detect_version(run_dir, versions)
        if v is None:
            continue
        baseline = run_dir.parent.parent.name
        model = run_dir.parent.name
        for metric, prefix in metric_files.items():
            for path in run_dir.glob(f"{prefix}_*.xlsx"):
                try:
                    df = pd.read_excel(path, sheet_name="Categorization")
                except (ValueError, FileNotFoundError):
                    continue
                if "Category" not in df.columns:
                    continue
                bucket = (raw[metric][v]
                            .setdefault(baseline, {})
                            .setdefault(model, [0] * len(categories)))
                for i, cat in enumerate(categories):
                    bucket[i] += int((df["Category"] == cat).sum())

    baselines = sorted({b for metric in raw.values() for v in metric.values() for b in v.keys()})
    models = sorted({m for metric in raw.values() for v in metric.values()
                     for b in v.values() for m in b.keys()})
    if not baselines or not models:
        return {"empty": True, "versions": versions, "baselines": [], "models": [],
                "categories": categories, "bert": {}, "rouge": {}}

    def to_pct(metric_key: str) -> dict[str, dict[str, dict[str, list[float]]]]:
        out: dict[str, dict[str, dict[str, list[float]]]] = {}
        for v in versions:
            out[v] = {}
            for b in baselines:
                out[v][b] = {}
                for m in models:
                    counts = raw[metric_key][v].get(b, {}).get(m, [0] * len(categories))
                    total = sum(counts)
                    out[v][b][m] = [round((c / total) * 100, 2) if total else 0.0
                                    for c in counts]
        return out

    return {
        "empty": False,
        "versions": versions, "baselines": baselines, "models": models,
        "categories": categories,
        "bert": to_pct("bert"), "rouge": to_pct("rouge"),
    }
