"""TL;DR KPI cards.

Four cards above the fold answering the most-asked questions:
  1. Best F1 (which model wins)
  2. Schema validity (does the JSON parse)
  3. Severity Macro-F1 (does it classify severity right)
  4. Exact Record Match (whole-vuln correctness)

Each card returns a dict the Jinja template renders directly — no Plotly
needed for static numbers, and rendering 4 cards as HTML is faster than
4 Plotly figures (Performance is UX).
"""
from __future__ import annotations

from metrics.plot.data_source import Dataset
from metrics.plot.themes import STATUS, categorize, CATEGORY_COLORS


def effective_f1_per_model(dataset: Dataset, version: str | None = None) -> dict[str, float]:
    """Per-model Effective F1 = (1 − omission_rate) · per_match_F1_Score.

    Coverage-aware quality score. Plain ``F1_Score`` is conditioned on
    successful match — a pipeline that conservatively skips hard
    vulnerabilities looks artificially perfect. Multiplying by recall
    (``1 − omission_rate``) penalises that selection bias and gives a
    single number that compares apples to apples across pipelines with
    different match rates.

    Returns ``{model: effective_f1}``; empty when either source is missing.
    """
    df = dataset.agg
    if version is not None:
        df = df[df["version"] == version]
    f1 = df[(df["source"] == "entity") & (df["metric"] == "F1_Score")]
    om = df[(df["source"] == "coverage") & (df["metric"] == "omission_rate")]
    if f1.empty or om.empty:
        return {}
    f1_per = f1.groupby("model")["mean"].mean()
    om_per = om.groupby("model")["mean"].mean()
    return {m: float((1 - om_per[m]) * f1_per[m])
            for m in f1_per.index.intersection(om_per.index)}


def _empty_card(title: str, subtitle: str) -> dict:
    return {"title": title, "value": "—", "subtitle": subtitle, "color": STATUS["neutral"], "trend": None}


def _safe_max(rows, key="mean"):
    rows = [r for r in rows if r.get(key) is not None]
    return max(rows, key=lambda r: r[key]) if rows else None


def best_f1_card(dataset: Dataset) -> dict:
    """Highest Effective F1 across models — coverage-aware so the winner
    isn't a selectively-matching pipeline. See :func:`effective_f1_per_model`.
    """
    eff = effective_f1_per_model(dataset)
    if not eff:
        return _empty_card("Best Effective F1", "no entity/coverage metrics yet")
    best_model, best_val = max(eff.items(), key=lambda kv: kv[1])
    band = categorize(best_val, "f1")
    return {
        "title": "Best Model — Effective F1",
        "value": f"{best_val:.3f}",
        "subtitle": f"{best_model} (recall × per-match F1)",
        "color": CATEGORY_COLORS[band],
        "trend": None,
    }


def schema_validity_card(dataset: Dataset) -> dict:
    """Mean ``schema_conformance_rate`` averaged across models."""
    df = dataset.agg
    schema = df[(df["source"] == "schema") & (df["metric"] == "schema_conformance_rate")]
    if schema.empty:
        return _empty_card("Schema validity", "no schema reports yet")
    rate = float(schema["mean"].mean())
    band = categorize(rate, "f1")
    return {
        "title": "Schema validity",
        "value": f"{rate * 100:.1f}%",
        "subtitle": "mean across models",
        "color": CATEGORY_COLORS[band],
        "trend": None,
    }


def severity_macro_f1_card(dataset: Dataset) -> dict:
    """Mean ``severity.macro_F1`` across models."""
    df = dataset.agg
    sev = df[(df["source"] == "severity") & (df["metric"] == "macro_F1")]
    if sev.empty:
        return _empty_card("Severity Macro-F1", "no severity matrices yet")
    val = float(sev["mean"].mean())
    band = categorize(val, "f1")
    return {
        "title": "Severity Macro-F1",
        "value": f"{val:.3f}",
        "subtitle": "mean across models",
        "color": CATEGORY_COLORS[band],
        "trend": None,
    }


def exact_record_match_card(dataset: Dataset) -> dict:
    """Highest ERM across models — the strict whole-vuln agreement."""
    df = dataset.agg
    erm = df[(df["source"] == "coverage") & (df["metric"] == "exact_record_match")]
    if erm.empty:
        return _empty_card("Exact Record Match", "no coverage reports yet")
    by_model = erm.groupby("model", as_index=False)["mean"].mean()
    best = _safe_max(by_model.to_dict("records"))
    if not best:
        return _empty_card("Exact Record Match", "no coverage reports yet")
    band = categorize(best["mean"], "f1")
    return {
        "title": "Best Exact Record Match",
        "value": f"{best['mean'] * 100:.1f}%",
        "subtitle": str(best["model"]),
        "color": CATEGORY_COLORS[band],
        "trend": None,
    }


def all_cards(dataset: Dataset) -> list[dict]:
    """Return all four cards in canonical reading order."""
    return [
        best_f1_card(dataset),
        schema_validity_card(dataset),
        severity_macro_f1_card(dataset),
        exact_record_match_card(dataset),
    ]


def leaderboard(dataset: Dataset) -> list[dict]:
    """One row per model with the four headline metrics, sorted by F1 desc.

    Empty cells become ``"—"`` so the template doesn't have to branch.
    """
    df = dataset.agg
    if df.empty:
        return []

    def by_model(source: str, metric: str, scale_pct: bool = False) -> dict:
        sub = df[(df["source"] == source) & (df["metric"] == metric)]
        if sub.empty:
            return {}
        agg = sub.groupby("model")["mean"].mean()
        return {m: (v * 100 if scale_pct else v) for m, v in agg.items()}

    f1     = by_model("entity",   "F1_Score")
    schema = by_model("schema",   "schema_conformance_rate", scale_pct=True)
    sev    = by_model("severity", "macro_F1")
    erm    = by_model("coverage", "exact_record_match",      scale_pct=True)
    eff    = effective_f1_per_model(dataset)  # coverage-aware combined score

    models = sorted({*f1, *schema, *sev, *erm, *eff})
    if not models:
        return []

    def fmt(v, *, pct: bool = False, places: int = 3) -> str:
        if v is None:
            return "—"
        return f"{v:.1f}%" if pct else f"{v:.{places}f}"

    rows = []
    for m in models:
        rows.append({
            "model":  m,
            "eff":    eff.get(m),
            "f1":     f1.get(m),
            "schema": schema.get(m),
            "sev":    sev.get(m),
            "erm":    erm.get(m),
            "eff_str":    fmt(eff.get(m)),
            "f1_str":     fmt(f1.get(m)),
            "schema_str": fmt(schema.get(m), pct=True),
            "sev_str":    fmt(sev.get(m)),
            "erm_str":    fmt(erm.get(m), pct=True),
        })
    # Order by Effective F1 — the coverage-aware winner deserves the top row.
    rows.sort(key=lambda r: (r["eff"] is None, -(r["eff"] or 0)))
    return rows
