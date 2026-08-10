"""PNG export — matplotlib with white background for paper figures.

One renderer per chart-data dict (the same dicts the HTML template
consumes via Chart.js). White background, paper-friendly typography,
high DPI.

Palette policy
──────────────
Most colors come from ``metrics.plot.themes`` so HTML and PNG stay
in sync (model palette, status, similarity stack accents on
charts not specifically below).

Two intentional divergences:

  * ``SEQUENTIAL_STOPS_LIGHT`` (light-bg ramp) is imported instead
    of ``SEQUENTIAL_STOPS`` (dark-bg). Same hue family (cyan/blue),
    inverted lightness so the ramp reads on white paper.

  * ``SIMILARITY_COLORS`` is **redefined locally below** with the
    legacy paper-figure palette (``#185542 / #1543a5 / #e6a70a /
    #a81e1e / #d3d5d8``). The HTML neon variant (``themes.SIMILARITY_COLORS``)
    is too saturated for print — historic paper figures use these
    exact tones and reviewers expect continuity with prior work.

If you change either of these, update ``themes.py``'s renderer-policy
comment so the divergence stays documented.
"""
from __future__ import annotations

import math
from pathlib import Path
from typing import Iterable

import numpy as np
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap

from metrics.plot.data_source import load_dataset
from metrics.plot.charts import (
    quality, robustness, diagnostic, drilldown, versioning,
)
from metrics.plot.themes import (
    MODEL_PALETTE, SEQUENTIAL_STOPS_LIGHT, STATUS, METRIC_COLORS,
)

FILL_ALPHA = 0.70  # matches the HTML report's ALPHA (B3 ≈ 0.70)

# Legacy palette — paper-figure tradition. Kept distinct from the HTML
# report's neon variant because the original PNGs read better on white.
SIMILARITY_COLORS = {
    "Highly Similar":     "#185542",
    "Moderately Similar": "#1543a5",
    "Slightly Similar":   "#e6a70a",
    "Divergent":          "#a81e1e",
    "Absent":             "#d3d5d8",
}


# Paper-friendly defaults.
plt.rcParams.update({
    "font.family":      "sans-serif",
    "font.sans-serif":  ["Inter", "Helvetica", "Arial", "DejaVu Sans"],
    "axes.facecolor":   "white",
    "figure.facecolor": "white",
    "savefig.facecolor":"white",
    "savefig.edgecolor":"white",
    "axes.edgecolor":   "#666",
    "axes.labelcolor":  "#222",
    "xtick.color":      "#444",
    "ytick.color":      "#444",
    "axes.grid":        True,
    "grid.color":       "#E5E5E5",
    "grid.linewidth":   0.7,
    "axes.spines.top":   False,
    "axes.spines.right": False,
})

CMAP = LinearSegmentedColormap.from_list("seq", [c for _, c in SEQUENTIAL_STOPS_LIGHT])


def _color_for(model: str, all_models: list[str]) -> str:
    return MODEL_PALETTE[sorted(all_models).index(model) % len(MODEL_PALETTE)] if model in all_models else "#888"


def _save(fig, path: Path):
    fig.savefig(path, dpi=200, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"[PNG] {path}")


def _empty_png(path: Path, msg: str, size=(8, 4)):
    fig, ax = plt.subplots(figsize=size)
    ax.text(0.5, 0.5, msg, ha="center", va="center", color="#888", fontsize=13, style="italic")
    ax.set_axis_off()
    _save(fig, path)


# ---------------------------------------------------------------------------
# Chart renderers.
# ---------------------------------------------------------------------------

def render_quality_prf(d: dict, path: Path):
    if d["empty"]:
        _empty_png(path, "no entity metrics yet"); return
    fig, ax = plt.subplots(figsize=(10, 5))
    models = d["models"]
    metrics = ["Precision", "Recall", "F1"]
    colors = {m: METRIC_COLORS[m] for m in ("Precision", "Recall", "F1")}
    width = 0.26
    x = np.arange(len(models))
    for i, m in enumerate(metrics):
        ax.bar(x + (i - 1) * width, d["values"][m], width=width,
               yerr=d["stds"][m], capsize=3, label=m,
               color=colors[m], alpha=FILL_ALPHA, edgecolor="white", linewidth=0.7,
               error_kw={"elinewidth": 1.0, "ecolor": "#444"})
    ax.set_xticks(x); ax.set_xticklabels(models, rotation=15, ha="right")
    ax.set_ylim(0, 1); ax.set_ylabel("Score")
    ax.set_title("Precision · Recall · F1 — ranked by F1 (mean ± σ)", loc="left", pad=12, fontsize=13, weight="bold")
    ax.legend(loc="upper right", frameon=False)
    _save(fig, path)


def render_quality_halluc(d: dict, path: Path):
    if d["empty"]:
        _empty_png(path, "no coverage metrics yet"); return
    fig, ax = plt.subplots(figsize=(8, 7))
    pts = d["points"]
    models = [p["model"] for p in pts]
    sorted_models = sorted(models)
    sizes = [max(120, min(900, p["n"] * 60)) for p in pts]
    for p, s in zip(pts, sizes):
        ax.scatter(p["halluc"], p["omiss"], s=s,
                   color=_color_for(p["model"], sorted_models),
                   alpha=FILL_ALPHA, edgecolor="white", linewidth=1.5)
        ax.annotate(p["model"], (p["halluc"], p["omiss"]),
                    xytext=(8, 8), textcoords="offset points", fontsize=10, color="#222")
    xmax = max(0.5, max(p["halluc"] for p in pts) * 1.2)
    ymax = max(0.5, max(p["omiss"] for p in pts) * 1.2)
    ax.plot([0, max(xmax, ymax)], [0, max(xmax, ymax)], color="#CCC", linestyle="--", linewidth=1)
    ax.set_xlim(0, xmax); ax.set_ylim(0, ymax)
    ax.set_xlabel("Hallucination rate"); ax.set_ylabel("Omission rate")
    ax.xaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v*100:.0f}%"))
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v*100:.0f}%"))
    ax.set_title("Hallucination × Omission — bottom-left is ideal", loc="left", pad=12, fontsize=13, weight="bold")
    _save(fig, path)


def render_quality_recall_f1(d: dict, path: Path):
    """Per-model Recall × per-match F1 scatter with iso-Effective-F1 contours."""
    if d["empty"]:
        _empty_png(path, d.get("reason", "no recall/F1 data yet")); return
    pts = d["points"]
    sorted_models = sorted({p["model"] for p in pts})
    fig, ax = plt.subplots(figsize=(8, 7))

    # Iso-contours: dashed grey curves at Eff = 0.5 / 0.7 / 0.85.
    import numpy as _np
    for eff in (0.5, 0.7, 0.85):
        rs = _np.linspace(eff, 1.0, 60)
        ax.plot(rs, eff / rs, color="#999", linestyle="--", linewidth=0.9, alpha=0.6, zorder=1)
        # Label the contour at recall=0.95.
        ax.text(0.97, eff / 0.97 + 0.012, f"Eff={eff}", color="#999",
                fontsize=8, ha="right", va="bottom")

    # Points + labels.
    for p in pts:
        c = _color_for(p["model"], sorted_models)
        ax.scatter(p["recall"], p["f1"], s=180, color=c, alpha=FILL_ALPHA,
                   edgecolor="white", linewidth=2, zorder=3)
        ax.annotate(p["model"], (p["recall"], p["f1"]),
                    xytext=(10, 0), textcoords="offset points",
                    fontsize=10, color="#222", va="center")
    ax.set_xlim(0, 1); ax.set_ylim(0, 1)
    ax.set_xlabel("Recall (1 − omission_rate)")
    ax.set_ylabel("Per-match F1 score")
    ax.xaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v*100:.0f}%"))
    ax.set_title("Recall × per-match F1 — iso-Effective-F1 contours dashed",
                 loc="left", pad=12, fontsize=13, weight="bold")
    _save(fig, path)


def render_robust_box(d: dict, path: Path):
    if d["empty"]:
        _empty_png(path, "no entity metrics yet"); return
    fig, ax = plt.subplots(figsize=(10, 5))
    models = d["models"]
    sorted_models = sorted(models)
    data = [d["values"][m] for m in models]
    bp = ax.boxplot(data, patch_artist=True, widths=0.55,
                    medianprops={"color": "#222", "linewidth": 1.5},
                    flierprops={"marker": "o", "markersize": 4})
    for patch, m in zip(bp["boxes"], models):
        c = _color_for(m, sorted_models)
        patch.set_facecolor(c); patch.set_alpha(0.40); patch.set_edgecolor(c); patch.set_linewidth(1.3)
    # Overlay run points.
    for i, vals in enumerate(data, start=1):
        jitter = np.random.RandomState(42 + i).uniform(-0.10, 0.10, size=len(vals))
        ax.scatter(np.full(len(vals), i) + jitter, vals,
                   color=_color_for(models[i-1], sorted_models), s=22, alpha=FILL_ALPHA,
                   edgecolor="white", linewidth=0.5, zorder=3)
    ax.set_xticklabels(models, rotation=15, ha="right")
    ax.set_ylim(0, 1); ax.set_ylabel("F1 score")
    ax.set_title("F1 distribution across runs — ordered by median", loc="left", pad=12, fontsize=13, weight="bold")
    _save(fig, path)


def render_wilcoxon(d: dict, path: Path):
    if d["empty"]:
        _empty_png(path, d.get("reason", "no data yet")); return
    models = d["models"]
    z = np.array([[float("nan") if v is None else v for v in row] for row in d["matrix"]])
    fig, ax = plt.subplots(figsize=(7, 6))
    # Invert (low p = significant = dark).
    img = ax.imshow(1 - z, cmap=CMAP, vmin=0, vmax=1)
    ax.set_xticks(range(len(models))); ax.set_xticklabels(models, rotation=35, ha="right")
    ax.set_yticks(range(len(models))); ax.set_yticklabels(models)
    for i in range(len(models)):
        for j in range(len(models)):
            v = z[i, j]
            if not math.isnan(v):
                lum = 1 - v  # in colormap space
                color = "#1F1F2A" if lum < 0.5 else "white"
                ax.text(j, i, f"{v:.3f}", ha="center", va="center", fontsize=9, color=color)
    cbar = fig.colorbar(img, ax=ax, fraction=0.04, pad=0.04)
    cbar.set_label("1 − p (Bonferroni)  →  significant", color="#222")
    ax.set_title("Pairwise Wilcoxon — darker = significant difference", loc="left", pad=12, fontsize=13, weight="bold")
    ax.grid(False)
    _save(fig, path)


def _heatmap(rows, cols, matrix, path, *, title, fmt, vmin=0, vmax=1, cbar_label="", figsize=None):
    z = np.array([[float("nan") if v is None else v for v in row] for row in matrix])
    h = max(3, 0.45 * len(rows) + 1.5)
    w = max(6, 0.7 * len(cols) + 2)
    fig, ax = plt.subplots(figsize=figsize or (w, h))
    img = ax.imshow(z, cmap=CMAP, vmin=vmin, vmax=vmax, aspect="auto")
    ax.set_xticks(range(len(cols))); ax.set_xticklabels(cols, rotation=30, ha="right")
    ax.set_yticks(range(len(rows))); ax.set_yticklabels(rows)
    for i in range(len(rows)):
        for j in range(len(cols)):
            v = z[i, j]
            if not math.isnan(v):
                norm = (v - vmin) / (vmax - vmin) if vmax > vmin else 0
                color = "#1F1F2A" if norm < 0.55 else "white"
                ax.text(j, i, fmt(v), ha="center", va="center", fontsize=9, color=color)
    cbar = fig.colorbar(img, ax=ax, fraction=0.04, pad=0.04)
    if cbar_label:
        cbar.set_label(cbar_label, color="#222")
    ax.set_title(title, loc="left", pad=12, fontsize=13, weight="bold")
    ax.grid(False)
    _save(fig, path)


def render_diag_schema_validity(d: dict, path: Path):
    if d["empty"]:
        _empty_png(path, "no schema conformance yet"); return
    fig, ax = plt.subplots(figsize=(max(7, 1.0 * len(d["models"]) + 3), 4))
    bars = ax.bar(d["models"], d["values"], color="#A3BE8C", alpha=FILL_ALPHA, edgecolor="white")
    for b, v in zip(bars, d["values"]):
        ax.text(b.get_x() + b.get_width()/2, v + 1.4, f"{v:.1f}%",
                ha="center", va="bottom", fontsize=9, color="#444")
    ax.set_ylim(0, 110); ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:.0f}%"))
    ax.set_ylabel("Conformance rate")
    ax.set_title("Schema validity per model — LLM compliance with V3 schema",
                 loc="left", pad=12, fontsize=13, weight="bold")
    ax.tick_params(axis="x", rotation=18)
    _save(fig, path)


def render_diag_json_validity(d: dict, path: Path):
    if d["empty"]:
        _empty_png(path, "no JSON validity yet"); return
    fig, ax = plt.subplots(figsize=(max(7, 1.0 * len(d["models"]) + 3), 4))
    bars = ax.bar(d["models"], d["values"], color="#88C0D0", alpha=FILL_ALPHA, edgecolor="white")
    for b, v in zip(bars, d["values"]):
        ax.text(b.get_x() + b.get_width()/2, v + 1.4, f"{v:.1f}%",
                ha="center", va="bottom", fontsize=9, color="#444")
    ax.set_ylim(0, 110); ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:.0f}%"))
    ax.set_ylabel("JSON valid")
    ax.set_title("JSON validity rate per model", loc="left", pad=12, fontsize=13, weight="bold")
    ax.tick_params(axis="x", rotation=18)
    _save(fig, path)


def render_diag_schema(d: dict, path: Path):
    if d["empty"]:
        _empty_png(path, "no schema reports yet"); return
    _heatmap(d["models"], d["fields"], d["matrix"], path,
             title="Schema conformance by model × field",
             fmt=lambda v: f"{v*100:.1f}%", cbar_label="conformance")


def render_diag_field_coverage(d: dict, path: Path):
    if d["empty"]:
        _empty_png(path, "no entity metrics yet"); return
    _heatmap(d["fields"], d["models"], d["matrix"], path,
             title=f"Per-field {d.get('metric','F1')} — fields ordered by overall difficulty",
             fmt=lambda v: f"{v:.2f}", cbar_label=d.get("metric", "F1"))


def render_diag_field_halluc(d: dict, path: Path):
    if d["empty"]:
        _empty_png(path, "no coverage per-field data yet"); return
    _heatmap(d["fields"], d["models"], d["matrix"], path,
             title="Per-field hallucination rate — fields ordered worst-at-bottom",
             fmt=lambda v: f"{v*100:.1f}%", cbar_label="hallucination rate")


def render_diag_field_omiss(d: dict, path: Path):
    if d["empty"]:
        _empty_png(path, "no coverage per-field data yet"); return
    _heatmap(d["fields"], d["models"], d["matrix"], path,
             title="Per-field omission rate — fields ordered worst-at-bottom",
             fmt=lambda v: f"{v*100:.1f}%", cbar_label="omission rate")


def render_diag_severity(d: dict, path: Path):
    if d["empty"]:
        _empty_png(path, "run severity metric first"); return
    models = d["models"]
    n = len(models)
    fig, axes = plt.subplots(1, n, figsize=(3.4 * n, 3.6), squeeze=False)
    z_max = d.get("z_max") or 1
    for i, m in enumerate(models):
        ax = axes[0, i]
        sub = d["matrices"][m]
        labels = sub["labels"]
        z = np.array(sub["matrix"], dtype=float)
        img = ax.imshow(z, cmap=CMAP, vmin=0, vmax=z_max, aspect="auto")
        ax.set_xticks(range(len(labels))); ax.set_xticklabels(labels, rotation=40, ha="right", fontsize=8)
        ax.set_yticks(range(len(labels))); ax.set_yticklabels(labels, fontsize=8)
        ax.set_title(m, fontsize=11, weight="bold")
        for r in range(len(labels)):
            for c in range(len(labels)):
                v = z[r, c]
                if v >= 0.5:
                    norm = v / z_max if z_max else 0
                    color = "#1F1F2A" if norm < 0.55 else "white"
                    ax.text(c, r, f"{v:.0f}", ha="center", va="center", fontsize=8, color=color)
        ax.grid(False)
    fig.colorbar(img, ax=axes[0, :].tolist(), fraction=0.025, pad=0.02, label="count")
    fig.suptitle("Severity confusion — true (rows) × predicted (cols)", x=0.02, ha="left", fontsize=13, weight="bold")
    _save(fig, path)


def render_drill_text(d: dict, path: Path):
    """N side-by-side heatmaps — one per available text scorer (BERT/ROUGE/Token-F1).

    PNG always renders the cross-baseline mean (``__all__`` key) — paper
    figures use the global view; per-baseline drill-down is HTML-only.
    """
    if d["empty"]:
        _empty_png(path, "no bert/rouge/token_f1 metrics yet"); return
    models, fields, available = d["models"], d["fields"], d["available"]
    labels = {"bert": "BERTScore", "rouge": "ROUGE-L", "token_f1": "Token-F1"}
    matrices = d["matrices"].get("__all__") or next(iter(d["matrices"].values()))
    h = max(3.5, 0.5 * len(models) + 1.5)
    w = max(6, 0.7 * len(fields) + 2)
    n = len(available)
    fig, axes = plt.subplots(1, n, figsize=(w * n, h), squeeze=False)
    for ax, source in zip(axes[0], available):
        mat = matrices[source]
        z = np.array([[float("nan") if v is None else v for v in row] for row in mat])
        img = ax.imshow(z, cmap=CMAP, vmin=0, vmax=1, aspect="auto")
        ax.set_xticks(range(len(fields))); ax.set_xticklabels(fields, rotation=30, ha="right")
        ax.set_yticks(range(len(models))); ax.set_yticklabels(models)
        for i in range(len(models)):
            for j in range(len(fields)):
                v = z[i, j]
                if not math.isnan(v):
                    color = "#1F1F2A" if v < 0.55 else "white"
                    ax.text(j, i, f"{v:.2f}", ha="center", va="center", fontsize=9, color=color)
        ax.set_title(labels.get(source, source), fontsize=12, weight="bold", loc="left")
        ax.grid(False)
        fig.colorbar(img, ax=ax, fraction=0.04, pad=0.04)
    fig.suptitle("Per-field text similarity — semantic (BERTScore) · lexical (ROUGE-L) · token (SQuAD-F1)",
                 x=0.02, ha="left", fontsize=13, weight="bold")
    fig.tight_layout(rect=[0, 0, 1, 0.94])
    _save(fig, path)


BASELINE_HATCHES = ['/', '+', '\\', '-', '|', '++', 'X', 'o', 'O', '.', '*', '//']


def _render_similarity_metric(d: dict, metric_key: str, label: str, path: Path):
    """One PNG per metric (BERT or ROUGE). Models on x-axis, hatched groups per baseline."""
    from matplotlib.patches import Patch

    cats = d["categories"]
    models = d["models"]
    baselines = d["baselines"]
    n_models, n_baselines = len(models), len(baselines)
    if n_models == 0 or n_baselines == 0:
        _empty_png(path, f"no {label} categorization yet"); return

    fig, ax = plt.subplots(figsize=(max(12, 2.2 * n_models + 4), 7))
    bar_width = 0.78 / n_baselines
    x = np.arange(n_models)
    per_baseline = d[metric_key]

    for b_idx, baseline in enumerate(baselines):
        hatch = BASELINE_HATCHES[b_idx % len(BASELINE_HATCHES)]
        for m_idx, model in enumerate(models):
            pct = per_baseline.get(baseline, {}).get(model, [0.0] * len(cats))
            bottom = 0.0
            bar_x = x[m_idx] + b_idx * bar_width
            for ci, cat in enumerate(cats):
                # Legacy similarity bars: full opacity so the bar color matches
                # the legend swatch (Patch is drawn without alpha).
                ax.bar(bar_x, pct[ci], bar_width, bottom=bottom,
                       color=SIMILARITY_COLORS[cat],
                       edgecolor="#cccccc", linewidth=0.7, hatch=hatch)
                bottom += pct[ci]

    ax.set_ylabel("Distribution (%)", fontsize=14)
    ax.set_xlabel("Model", fontsize=14)
    ax.set_ylim(0, 100)
    ax.set_title(f"Similarity Category Distribution\n{label}", fontsize=15, weight="bold")
    ax.set_xticks(x + bar_width * (n_baselines - 1) / 2)
    ax.set_xticklabels([m.capitalize() for m in models], fontsize=12)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    ax.set_axisbelow(True)

    cat_patches = [Patch(facecolor=SIMILARITY_COLORS[c], edgecolor="#cccccc", linewidth=0.7, label=c)
                   for c in cats]
    bl_patches = [Patch(facecolor="#cccccc", edgecolor="#333",
                        hatch=BASELINE_HATCHES[i % len(BASELINE_HATCHES)], label=b)
                  for i, b in enumerate(baselines)]
    fig.legend(handles=cat_patches, loc="lower center", bbox_to_anchor=(0.5, 0.02),
               ncol=len(cats), title="Category", frameon=True, fontsize=11, title_fontsize=12)
    fig.legend(handles=bl_patches, loc="lower center", bbox_to_anchor=(0.5, -0.05),
               ncol=min(n_baselines, 4), title="Baseline (pattern)", frameon=True,
               fontsize=11, title_fontsize=12)
    fig.tight_layout(rect=[0, 0.12, 1, 1])
    _save(fig, path)


def render_drill_similarity_bert(d: dict, path: Path):
    if d["empty"]:
        _empty_png(path, "no bert categorization yet"); return
    _render_similarity_metric(d, "bert", "BERT", path)


def render_drill_similarity_rouge(d: dict, path: Path):
    if d["empty"]:
        _empty_png(path, "no rouge categorization yet"); return
    _render_similarity_metric(d, "rouge", "ROUGE", path)


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# §0 — pipeline-version comparison (paper-only; no HTML twin).
# ---------------------------------------------------------------------------

def _version_color(version: str, all_versions: list[str]) -> str:
    """Stable color per version (Nord palette, alphabetical assignment)."""
    if not all_versions:
        return STATUS["neutral"]
    idx = sorted(all_versions).index(version) if version in all_versions else 0
    return MODEL_PALETTE[idx % len(MODEL_PALETTE)]


def render_v2_v3_headline(d: dict, path: Path):
    """Grouped bars: one panel per metric, all versions side by side per model."""
    if d["empty"]:
        _empty_png(path, "no per-version metrics yet"); return
    models, versions, blocks = d["models"], d["versions"], d["metrics"]
    n_panels = len(blocks)
    cols = min(2, n_panels)
    rows = math.ceil(n_panels / cols)
    fig, axes = plt.subplots(rows, cols, figsize=(7 * cols, 4.2 * rows), squeeze=False)

    width = 0.36
    x = np.arange(len(models))
    for idx, block in enumerate(blocks):
        ax = axes[idx // cols][idx % cols]
        for vi, v in enumerate(versions):
            vals = [(0 if x is None else x) for x in block["values"][v]]
            ax.bar(x + (vi - (len(versions) - 1) / 2) * width, vals, width=width,
                   label=v, color=_version_color(v, versions), alpha=FILL_ALPHA,
                   edgecolor="white", linewidth=0.7)
            for xi, val in zip(x + (vi - (len(versions) - 1) / 2) * width, vals):
                if val > 0:
                    fmt = f"{val:.1f}%" if block["is_pct"] else f"{val:.2f}"
                    ax.text(xi, val + (1.2 if block["is_pct"] else 0.012),
                            fmt, ha="center", va="bottom", fontsize=8, color="#444")
        ax.set_title(block["label"], fontsize=12, weight="bold", loc="left")
        ax.set_xticks(x); ax.set_xticklabels(models, rotation=18, ha="right", fontsize=10)
        if block["is_pct"]:
            ax.set_ylim(0, 110); ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:.0f}%"))
        else:
            ax.set_ylim(0, 1.05)
        ax.legend(frameon=False, fontsize=10)
    for j in range(n_panels, rows * cols):
        axes[j // cols][j % cols].set_visible(False)
    fig.suptitle(f"Headline metrics by version ({', '.join(versions)})",
                 x=0.02, ha="left", fontsize=14, weight="bold")
    fig.tight_layout(rect=[0, 0, 1, 0.94])
    _save(fig, path)


_SIMILARITY_PNG_COLORS = {
    "Highly Similar":     "#185542",
    "Moderately Similar": "#1543a5",
    "Slightly Similar":   "#e6a70a",
    "Divergent":          "#a81e1e",
    "Absent":             "#d3d5d8",
}


def render_v2_v3_similarity(d: dict, path: Path):
    """Stacked similarity buckets per (version, model), BERT and ROUGE side by side.

    Two panels (BERT, ROUGE). Inside each panel, every model has N adjacent
    stacked bars — one per version — using the legacy paper palette to stay
    consistent with the standalone ``stacked_similarity_*.png`` figures.
    """
    if d["empty"]:
        _empty_png(path, "no per-version categorization yet"); return

    from matplotlib.patches import Patch

    versions = d["versions"]
    models = d["models"]
    cats = d["categories"]
    n_versions = len(versions)
    n_models = len(models)

    bar_w = 0.78 / n_versions
    x = np.arange(n_models)

    fig, axes = plt.subplots(1, 2, figsize=(max(13, 2.5 * n_models + 5), 7), sharey=True)

    for ax, metric_key, label in [(axes[0], "bert", "BERT"), (axes[1], "rouge", "ROUGE")]:
        per_version = d[metric_key]
        for vi, v in enumerate(versions):
            offset = (vi - (n_versions - 1) / 2) * bar_w
            for m_idx, model in enumerate(models):
                pct = per_version[v].get(model, [0.0] * len(cats))
                bottom = 0.0
                bar_x = x[m_idx] + offset
                for ci, cat in enumerate(cats):
                    ax.bar(bar_x, pct[ci], bar_w, bottom=bottom,
                           color=_SIMILARITY_PNG_COLORS[cat], edgecolor="#cccccc",
                           linewidth=0.6)
                    bottom += pct[ci]
            # Version label under each group of bars.
            for m_idx in range(n_models):
                ax.text(x[m_idx] + offset, -3.5, v, ha="center", va="top",
                        fontsize=8, color=_version_color(v, versions), weight="bold")

        ax.set_title(label, fontsize=13, weight="bold", loc="left")
        ax.set_ylim(0, 100)
        ax.set_xticks(x)
        ax.set_xticklabels([m.capitalize() for m in models], fontsize=11)
        ax.tick_params(axis="x", which="major", pad=18)  # leave room for version labels
        if metric_key == "bert":
            ax.set_ylabel("Distribution (%)", fontsize=12)
        ax.grid(axis="y", linestyle="--", alpha=0.35)
        ax.set_axisbelow(True)

    cat_patches = [Patch(facecolor=_SIMILARITY_PNG_COLORS[c], edgecolor="#cccccc",
                         linewidth=0.6, label=c) for c in cats]
    fig.legend(handles=cat_patches, loc="lower center", bbox_to_anchor=(0.5, 0.0),
               ncol=len(cats), title="Category", frameon=True, fontsize=11, title_fontsize=12)
    fig.suptitle(f"Similarity distribution by version ({', '.join(versions)})",
                 x=0.02, ha="left", fontsize=14, weight="bold")
    fig.tight_layout(rect=[0, 0.08, 1, 0.95])
    _save(fig, path)


def render_v2_v3_json_validity(d: dict, path: Path):
    """Grouped bars: JSON validity rate (%) per model, V2 vs V3."""
    if d["empty"]:
        _empty_png(path, "no JSON validity data yet"); return
    versions, models, values = d["versions"], d["models"], d["values"]
    width = 0.36
    x = np.arange(len(models))
    fig, ax = plt.subplots(figsize=(max(9, 1.4 * len(models) + 4), 4.6))
    for vi, v in enumerate(versions):
        vals = [(0 if x is None else x) for x in values[v]]
        bars = ax.bar(x + (vi - (len(versions) - 1) / 2) * width, vals, width=width,
                      label=v, color=_version_color(v, versions), alpha=FILL_ALPHA,
                      edgecolor="white", linewidth=0.7)
        for b, val in zip(bars, vals):
            if val > 0:
                ax.text(b.get_x() + b.get_width() / 2, val + 1.4, f"{val:.0f}%",
                        ha="center", va="bottom", fontsize=9, color="#444")
    ax.set_xticks(x); ax.set_xticklabels(models, rotation=18, ha="right", fontsize=10)
    ax.set_ylim(0, 110)
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:.0f}%"))
    ax.set_ylabel("JSON validity rate")
    ax.set_title(f"JSON validity by version ({', '.join(versions)})",
                 loc="left", pad=12, fontsize=14, weight="bold")
    ax.legend(frameon=False, fontsize=10)
    _save(fig, path)


# ---------------------------------------------------------------------------
# Pipeline.
# ---------------------------------------------------------------------------

def export_all(roots: Iterable[Path], output_dir: Path) -> list[Path]:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    dataset = load_dataset(roots)

    plan = [
        ("quality_prf",          quality.precision_recall_f1(dataset),                 render_quality_prf),
        ("quality_halluc",       quality.hallucination_omission_scatter(dataset),      render_quality_halluc),
        ("quality_recall_f1",    quality.recall_vs_f1_scatter(dataset),                render_quality_recall_f1),
        ("robust_f1_box",        robustness.f1_distribution_box(dataset),              render_robust_box),
        ("robust_wilcoxon",      robustness.wilcoxon_pvalue_heatmap(dataset),          render_wilcoxon),
        ("diag_schema",          diagnostic.schema_conformance_heatmap(dataset),       render_diag_schema),
        ("diag_schema_validity", diagnostic.schema_validity_per_model(dataset),        render_diag_schema_validity),
        ("diag_json_validity",   diagnostic.json_validity_per_model(dataset),          render_diag_json_validity),
        ("diag_field_halluc",    diagnostic.field_hallucination_omission_heatmap(dataset, "hallucination_rate"), render_diag_field_halluc),
        ("diag_field_omiss",     diagnostic.field_hallucination_omission_heatmap(dataset, "omission_rate"),      render_diag_field_omiss),
        ("diag_severity",        diagnostic.severity_confusion_small_multiples(dataset), render_diag_severity),
        ("diag_field_coverage",  diagnostic.field_coverage_heatmap(dataset),           render_diag_field_coverage),
        ("drill_text_per_field",   drilldown.text_similarity_by_field(dataset),        render_drill_text),
        ("stacked_similarity_bert",  drilldown.similarity_distribution(dataset),       render_drill_similarity_bert),
        ("stacked_similarity_rouge", drilldown.similarity_distribution(dataset),       render_drill_similarity_rouge),
        # §0 — pipeline-version comparison (paper-only)
        ("version_headline",       versioning.headline_per_version(dataset),           render_v2_v3_headline),
        ("version_json_validity",  versioning.json_validity_per_version(dataset),      render_v2_v3_json_validity),
        ("version_similarity",     versioning.similarity_distribution_per_version(dataset), render_v2_v3_similarity),
    ]

    written: list[Path] = []
    for stem, data, render in plan:
        out = output_dir / f"{stem}.png"
        try:
            render(data, out)
        except Exception as exc:  # pragma: no cover
            print(f"[PNG] failed {stem}: {exc}")
            continue
        if out.exists():
            written.append(out)
    return written


__all__ = ["export_all"]
