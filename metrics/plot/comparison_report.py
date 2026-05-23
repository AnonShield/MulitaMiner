"""HTML pipeline-comparison report orchestrator (pairwise: V2 vs V3 and similar).

Used when ``metrics.plot.metrics`` detects exactly 2 versions in the dataset.
Pairwise only — the delta KPIs, paired Wilcoxon, and wide leaderboard are
designed around a single A/B comparison; 3+ versions must use the regular
per-section report or a separate multi-version flow.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Iterable

from jinja2 import Environment, FileSystemLoader

from metrics.plot.data_source import load_dataset
from metrics.plot.charts import comparison, versioning
from metrics.plot.themes import (
    MODEL_PALETTE, SIMILARITY_COLORS, THEME_TOKENS,
)


_TEMPLATE_DIR = Path(__file__).parent / "templates"
_TEMPLATE_FILE = "comparison.jinja2"


def _headline_chart_data(dataset) -> dict:
    """Per-metric, per-(model, version) values for the grouped-bar charts.

    Reshapes ``versioning.headline_per_version`` so each block has
    ``values_by_model[model][version] = float`` — exactly what the
    template's Chart.js loop expects.
    """
    src = versioning.headline_per_version(dataset)
    if src.get("empty"):
        return {"empty": True, "metrics": []}
    blocks = []
    versions = src["versions"]
    models = src["models"]
    for block in src["metrics"]:
        # Find the (source, metric_key) the renderer needs to dispatch off — derive
        # from label by re-mapping against the canonical _HEADLINE_METRICS.
        from metrics.plot.charts.versioning import _HEADLINE_METRICS
        spec = next((s for s in _HEADLINE_METRICS if s[2] == block["label"]), None)
        metric_key = spec[1] if spec else block["label"]

        values_by_model = {}
        for m_idx, m in enumerate(models):
            values_by_model[m] = {v: block["values"][v][m_idx] for v in versions}
        blocks.append({
            "label": block["label"], "metric": metric_key, "is_pct": block["is_pct"],
            "values_by_model": values_by_model, "versions": versions,
        })
    return {"empty": False, "metrics": blocks}


def build_comparison_report(roots: Iterable[Path], output_dir: Path) -> Path:
    """Build the pairwise comparison HTML report. Requires exactly 2 versions."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    dataset = load_dataset(roots)
    versions = list(dataset.versions or [])
    if len(versions) != 2:
        raise ValueError(
            f"comparison report requires exactly 2 versions, got {len(versions)}: "
            f"{versions}. Pass roots containing only 2 versions (e.g. v2 and v3)."
        )

    kpis = comparison.headline_kpis_with_delta(dataset)
    leaderboard = comparison.leaderboard_wide(dataset)
    wilcoxon = comparison.wilcoxon_pairs(dataset)
    similarity = comparison.similarity_per_baseline_per_version(dataset)
    cv = comparison.cv_per_version(dataset)
    schema_field_failures = comparison.schema_field_failures_per_version(dataset)

    headline = _headline_chart_data(dataset)
    chart_data = {
        "headline":     headline,
        "json_validity": versioning.json_validity_per_version(dataset),
        "similarity":   similarity,
        "recall_vs_f1": comparison.recall_vs_f1_scatter(dataset),
        "cv":           comparison.cv_per_version(dataset),
    }

    env = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)))
    tmpl = env.get_template(_TEMPLATE_FILE)
    html = tmpl.render(
        report_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        versions=list(dataset.versions or []),
        models=sorted(dataset.models or []),
        kpis=kpis,
        leaderboard=leaderboard,
        wilcoxon=wilcoxon,
        cv=cv,
        schema_field_failures=schema_field_failures,
        chart_data_headline=headline,
        chart_data_json=json.dumps(chart_data, ensure_ascii=False),
        versions_json=json.dumps(list(dataset.versions or [])),
        palette_json=json.dumps(MODEL_PALETTE),
        similarity_colors_json=json.dumps(SIMILARITY_COLORS),
        theme_tokens_json=json.dumps(THEME_TOKENS),
    )

    out_path = output_dir / f"metrics_comparison_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    out_path.write_text(html, encoding="utf-8")
    return out_path


__all__ = ["build_comparison_report"]
