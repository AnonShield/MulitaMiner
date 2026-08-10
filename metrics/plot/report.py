"""HTML report orchestrator.

Reads the dataset, extracts each chart's data dict, dumps everything as
JSON into the Jinja template. Chart.js renders bars/scatter/box on the
client; heatmaps render as plain CSS grids server-side.
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Iterable

from jinja2 import Environment, FileSystemLoader

from metrics.plot.data_source import load_dataset
from metrics.plot.charts import (
    kpi, quality, robustness, diagnostic, drilldown,
    consistency, missed_vulns,
)
from metrics.plot.themes import (
    MODEL_PALETTE, SEQUENTIAL_STOPS, SIMILARITY_COLORS,
    METRIC_COLORS, THEME_TOKENS,
)


_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
_TEMPLATE_FILE = "report.jinja2"


def build_report(roots: Iterable[Path], output_dir: Path) -> Path:
    """Build the report and return the written .html path."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    dataset = load_dataset(roots)

    cards = kpi.all_cards(dataset)
    leaderboard_rows = kpi.leaderboard(dataset)
    consistency_rows = consistency.consistency_table(dataset)

    chart_data = {
        "quality_prf":          quality.precision_recall_f1(dataset),
        "quality_halluc":       quality.hallucination_omission_scatter(dataset),
        "quality_recall_f1":    quality.recall_vs_f1_scatter(dataset),
        "robust_box":           robustness.f1_distribution_box(dataset),
        "robust_wilcoxon":      robustness.wilcoxon_pvalue_heatmap(dataset),
        "diag_schema":          diagnostic.schema_conformance_heatmap(dataset),
        "diag_schema_validity": diagnostic.schema_validity_per_model(dataset),
        "diag_json_validity":   diagnostic.json_validity_per_model(dataset),
        "diag_severity":        diagnostic.severity_confusion_small_multiples(dataset),
        "diag_field_coverage":  diagnostic.field_coverage_heatmap(dataset),
        "diag_field_halluc":    diagnostic.field_hallucination_omission_heatmap(dataset, kind="hallucination_rate"),
        "diag_field_omiss":     diagnostic.field_hallucination_omission_heatmap(dataset, kind="omission_rate"),
        "diag_extra_fields":    diagnostic.extra_fields_rate_per_model(dataset),
        "diag_missing_fields":  diagnostic.missing_fields_top_n(dataset),
        "drill_text":           drilldown.text_similarity_by_field(dataset),
        "drill_similarity":     drilldown.similarity_distribution(dataset),
        "missed_vulns":         missed_vulns.top_absent_per_baseline(dataset),
    }

    env = Environment(loader=FileSystemLoader(_TEMPLATE_DIR))
    tmpl = env.get_template(_TEMPLATE_FILE)
    html = tmpl.render(
        report_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        roots=[str(r) for r in roots],
        models=dataset.models,
        targets=dataset.targets,
        versions=dataset.versions,
        n_runs_total=int(dataset.long.groupby(["target", "model"])["run"].nunique().sum())
                      if not dataset.long.empty else 0,
        cards=cards,
        leaderboard=leaderboard_rows,
        consistency=consistency_rows,
        sources=dataset.sources,
        chart_data_json=json.dumps(chart_data, ensure_ascii=False),
        palette_json=json.dumps(MODEL_PALETTE),
        ramp_json=json.dumps(SEQUENTIAL_STOPS),
        similarity_colors_json=json.dumps(SIMILARITY_COLORS),
        metric_colors_json=json.dumps(METRIC_COLORS),
        theme_tokens_json=json.dumps(THEME_TOKENS),
    )

    out_path = output_dir / f"metrics_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    out_path.write_text(html, encoding="utf-8")
    return out_path


__all__ = ["build_report"]
