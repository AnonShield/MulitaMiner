"""Generate visualization charts from evaluation_report.xlsx."""
import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

sns.set_theme(style="whitegrid", context="talk")

CATEGORICAL_FIELDS = ["severity", "protocol", "source", "cvss", "port"]
# log_method is excluded from aggregate plots: the OpenVAS native CSV does not
# export this field, so the baseline is always empty and ROUGE-L mean is 0
# by default of "no comparable cases", not by poor LLM quality.
TEXT_FIELDS = [
    "description", "detection_result", "detection_method",
    "product_detection_result", "impact", "solution", "insight",
]
TEXT_FIELDS_FULL = TEXT_FIELDS + ["log_method"]


def plot_performance_curves(summary, out_dir):
    """Line chart of P/R/F1 across PDFs sorted by F1 (worst to best)."""
    df = summary.sort_values("f1", ascending=True).reset_index(drop=True)
    df["rank"] = range(1, len(df) + 1)

    fig, ax = plt.subplots(figsize=(14, 6))
    ax.plot(df["rank"], df["f1"], color="#f59e0b", linewidth=2, label="F1")
    ax.plot(df["rank"], df["precision"], color="#3b82f6", linewidth=1.5, alpha=0.8, label="Precision")
    ax.plot(df["rank"], df["recall"], color="#10b981", linewidth=1.5, alpha=0.8, label="Recall")
    for metric, color in [("f1", "#f59e0b"), ("precision", "#3b82f6"), ("recall", "#10b981")]:
        ax.axhline(df[metric].mean(), color=color, linestyle="--", alpha=0.4, linewidth=1)
    ax.set_ylim(0, 1.05)
    ax.set_xlabel("PDF (ordenado por F1, do pior pro melhor)")
    ax.set_ylabel("score")
    ax.set_title("Curvas de Precision / Recall / F1 ao longo dos 129 PDFs")
    ax.legend(loc="lower right")
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_dir / "00e_performance_curves.png", dpi=120, bbox_inches="tight")
    plt.close(fig)


def plot_ecdf(summary, out_dir):
    """Empirical CDF of P/R/F1: 'X% of PDFs have score >= Y'."""
    fig, ax = plt.subplots(figsize=(11, 7))
    for metric, color in [("precision", "#3b82f6"), ("recall", "#10b981"), ("f1", "#f59e0b")]:
        sorted_v = np.sort(summary[metric].values)
        ecdf = np.arange(1, len(sorted_v) + 1) / len(sorted_v)
        ax.plot(sorted_v, 1 - ecdf, color=color, linewidth=2.5, label=metric.capitalize())
    for thresh in [0.7, 0.8, 0.9]:
        ax.axvline(thresh, color="gray", linestyle=":", alpha=0.4)
        ax.text(thresh, 1.02, f"{thresh}", ha="center", fontsize=10, color="gray")
    ax.set_xlim(0, 1.02)
    ax.set_ylim(0, 1.05)
    ax.set_xlabel("score (Y)")
    ax.set_ylabel("fração de PDFs com score >= Y")
    ax.set_title("Curva de fração de PDFs por score (CDF complementar)")
    ax.legend(loc="lower left")
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_dir / "00f_ecdf.png", dpi=120, bbox_inches="tight")
    plt.close(fig)


def plot_pairplot(summary, out_dir):
    """Scatter matrix among the 5 main dimensions."""
    cols = ["precision", "recall", "f1", "n_baseline", "n_pred"]
    df = summary[cols].copy()
    g = sns.pairplot(
        df, diag_kind="kde", height=2.4, aspect=1.2,
        plot_kws={"alpha": 0.5, "s": 20, "color": "#f59e0b"},
        diag_kws={"fill": True, "color": "#3b82f6"},
    )
    g.fig.suptitle("Matriz de dispersão — métricas principais (129 PDFs)", y=1.01)
    g.fig.savefig(out_dir / "00g_pairplot.png", dpi=120, bbox_inches="tight")
    plt.close(g.fig)


def plot_kpi_dashboard(summary, agg_severity, out_dir):
    """One-glance dashboard with the headline numbers."""
    f1_mean = summary["f1"].mean()
    prec_mean = summary["precision"].mean()
    rec_mean = summary["recall"].mean()
    cat_cols = [f"{f}_acc" for f in CATEGORICAL_FIELDS]
    cat_mean = summary[cat_cols].mean().mean()
    text_cols = [f"{f}_rouge" for f in TEXT_FIELDS]
    text_mean = summary[text_cols].mean().mean()
    refs_f1 = summary["references_f1"].mean()
    overall = np.mean([f1_mean, cat_mean, text_mean, refs_f1])

    kpis = [
        ("F1 (detecção)", f1_mean, "#f59e0b"),
        ("Precision", prec_mean, "#3b82f6"),
        ("Recall", rec_mean, "#10b981"),
        ("Campos categóricos", cat_mean, "#8b5cf6"),
        ("Campos texto (ROUGE-L)", text_mean, "#14b8a6"),
        ("Similaridade geral", overall, "#dc2626"),
    ]

    fig, axes = plt.subplots(2, 3, figsize=(15, 8))
    fig.suptitle(
        f"Avaliação do LLM vs baseline — {len(summary)} PDFs (médias macro)",
        fontsize=18, y=1.02,
    )
    for ax, (label, value, color) in zip(axes.flat, kpis):
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.axis("off")
        ax.add_patch(plt.Rectangle((0.05, 0.1), 0.9, 0.8, facecolor=color, alpha=0.12,
                                    edgecolor=color, linewidth=2))
        ax.text(0.5, 0.62, f"{value:.1%}", ha="center", va="center",
                fontsize=42, color=color, fontweight="bold")
        ax.text(0.5, 0.28, label, ha="center", va="center", fontsize=14, color="#374151")
    fig.tight_layout()
    fig.savefig(out_dir / "00_kpi_dashboard.png", dpi=120, bbox_inches="tight")
    plt.close(fig)


def plot_field_fidelity(summary, out_dir):
    """One bar per field showing similarity to ground truth (0-1)."""
    rows = []
    for f in CATEGORICAL_FIELDS:
        rows.append({"field": f, "score": summary[f"{f}_acc"].mean(), "kind": "categórico"})
    rows.append({"field": "references", "score": summary["references_f1"].mean(), "kind": "set (F1)"})
    for f in TEXT_FIELDS:
        rows.append({"field": f, "score": summary[f"{f}_rouge"].mean(), "kind": "texto (ROUGE-L)"})
    df = pd.DataFrame(rows).sort_values("score", ascending=True)

    palette = {"categórico": "#8b5cf6", "set (F1)": "#f59e0b", "texto (ROUGE-L)": "#14b8a6"}
    fig, ax = plt.subplots(figsize=(12, 9))
    bars = ax.barh(df["field"], df["score"], color=df["kind"].map(palette))
    for bar, score in zip(bars, df["score"]):
        ax.text(score + 0.01, bar.get_y() + bar.get_height() / 2,
                f"{score:.1%}", va="center", fontsize=11)
    ax.set_xlim(0, 1.1)
    ax.set_xlabel("similaridade ao baseline (0 a 1)")
    ax.set_title("Fidelidade do LLM por campo (média nos 129 PDFs)")
    handles = [plt.Rectangle((0, 0), 1, 1, color=c) for c in palette.values()]
    ax.legend(handles, palette.keys(), loc="lower right", title="tipo de campo")
    fig.tight_layout()
    fig.savefig(out_dir / "00b_field_fidelity.png", dpi=120, bbox_inches="tight")
    plt.close(fig)


def plot_field_heatmap(summary, out_dir):
    """Heatmap of field fidelity grouped by F1 quality buckets.

    Rows = buckets of PDFs by F1 (worst -> best); columns = fields;
    cells = mean score in that bucket. Annotated, compact, and readable.
    """
    cols = (
        [(f"{f}_acc", f) for f in CATEGORICAL_FIELDS]
        + [("references_f1", "references")]
        + [(f"{f}_rouge", f) for f in TEXT_FIELDS]
    )
    df = summary.copy()
    df = df.sort_values("f1", ascending=True).reset_index(drop=True)

    n = len(df)
    bucket_defs = [
        ("10 piores",   df.iloc[:10]),
        ("quartil 1",   df.iloc[:n // 4]),
        ("quartil 2",   df.iloc[n // 4: n // 2]),
        ("quartil 3",   df.iloc[n // 2: 3 * n // 4]),
        ("quartil 4",   df.iloc[3 * n // 4:]),
        ("10 melhores", df.iloc[-10:]),
        ("todos",       df),
    ]

    rows = {}
    f1_summary = {}
    for label, sub in bucket_defs:
        if len(sub) == 0:
            continue
        rows[label] = [sub[col].mean() for col, _ in cols]
        f1_summary[label] = sub["f1"].mean()

    matrix = pd.DataFrame(
        rows, index=[label for _, label in cols],
    ).T
    y_labels = [f"{lab}  (F1 méd. {f1_summary[lab]:.2f}, n={len(s)})"
                for lab, s in bucket_defs if len(s) > 0]

    fig, ax = plt.subplots(figsize=(13, 6))
    sns.heatmap(
        matrix, vmin=0, vmax=1, cmap="RdYlGn",
        annot=True, fmt=".2f", annot_kws={"size": 11},
        cbar_kws={"label": "similaridade ao baseline (0 a 1)"},
        linewidths=0.5, linecolor="white",
        yticklabels=y_labels, ax=ax,
    )
    ax.set_xlabel("campo")
    ax.set_ylabel("grupo de PDFs (por F1)")
    ax.set_title("Fidelidade por campo × grupo de PDFs (média)")
    plt.xticks(rotation=30, ha="right")
    plt.yticks(rotation=0)
    fig.tight_layout()
    fig.savefig(out_dir / "00d_field_heatmap.png", dpi=120, bbox_inches="tight")
    plt.close(fig)


def plot_field_radar(summary, out_dir):
    """Radar chart consolidating fidelity across all fields."""
    fields, scores = [], []
    for f in CATEGORICAL_FIELDS:
        fields.append(f); scores.append(summary[f"{f}_acc"].mean())
    fields.append("references"); scores.append(summary["references_f1"].mean())
    for f in TEXT_FIELDS:
        fields.append(f); scores.append(summary[f"{f}_rouge"].mean())

    angles = np.linspace(0, 2 * np.pi, len(fields), endpoint=False).tolist()
    scores_closed = scores + scores[:1]
    angles_closed = angles + angles[:1]

    fig, ax = plt.subplots(figsize=(11, 11), subplot_kw={"projection": "polar"})
    ax.plot(angles_closed, scores_closed, color="#dc2626", linewidth=2)
    ax.fill(angles_closed, scores_closed, color="#dc2626", alpha=0.2)
    ax.set_xticks(angles)
    ax.set_xticklabels(fields, fontsize=11)
    ax.set_ylim(0, 1)
    ax.set_yticks([0.25, 0.5, 0.75, 1.0])
    ax.set_yticklabels(["25%", "50%", "75%", "100%"], fontsize=10)
    ax.set_title("Fidelidade do LLM por campo (radar) — média nos 129 PDFs", pad=30)
    fig.tight_layout()
    fig.savefig(out_dir / "00c_field_radar.png", dpi=120, bbox_inches="tight")
    plt.close(fig)


def plot_prf_distribution(summary, out_dir):
    fig, axes = plt.subplots(1, 3, figsize=(18, 5))
    for ax, metric, color in zip(axes, ["precision", "recall", "f1"], ["#3b82f6", "#10b981", "#f59e0b"]):
        sns.histplot(summary[metric], bins=30, ax=ax, color=color, kde=True)
        ax.axvline(summary[metric].mean(), color="black", linestyle="--", label=f"média={summary[metric].mean():.3f}")
        ax.axvline(summary[metric].median(), color="red", linestyle=":", label=f"mediana={summary[metric].median():.3f}")
        ax.set_title(metric.capitalize())
        ax.set_xlim(0, 1.05)
        ax.set_xlabel(metric)
        ax.legend()
    fig.suptitle("Distribuição de Precision / Recall / F1 nos 129 PDFs", y=1.02)
    fig.tight_layout()
    fig.savefig(out_dir / "01_prf_distribution.png", dpi=120, bbox_inches="tight")
    plt.close(fig)


def plot_pr_scatter(summary, out_dir):
    fig, ax = plt.subplots(figsize=(10, 8))
    sns.scatterplot(
        data=summary, x="recall", y="precision",
        size="n_baseline", hue="f1", palette="viridis",
        sizes=(30, 400), alpha=0.7, ax=ax,
    )
    ax.set_xlim(0, 1.05)
    ax.set_ylim(0, 1.05)
    ax.plot([0, 1], [0, 1], "k--", alpha=0.3)
    ax.set_title("Precision vs Recall por PDF (tamanho = nº de vulns no baseline)")
    fig.tight_layout()
    fig.savefig(out_dir / "02_pr_scatter.png", dpi=120, bbox_inches="tight")
    plt.close(fig)


def plot_severity_recall(agg_severity, out_dir):
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "LOG"]
    data = agg_severity.set_index("severity").reindex(order).reset_index().dropna()
    fig, ax = plt.subplots(figsize=(10, 6))
    sns.barplot(
        data=data, x="severity", y="recall_micro",
        palette=["#dc2626", "#ea580c", "#f59e0b", "#84cc16", "#6b7280"], ax=ax,
    )
    for i, (_, r) in enumerate(data.iterrows()):
        ax.text(
            i, r["recall_micro"] + 0.01,
            f"{int(r['matched_total'])}/{int(r['baseline_total'])}\n{r['recall_micro']:.1%}",
            ha="center", fontsize=11,
        )
    ax.set_ylim(0, 1.1)
    ax.set_title("Recall (micro) por severidade — agregado nos 129 PDFs")
    ax.set_ylabel("recall")
    fig.tight_layout()
    fig.savefig(out_dir / "03_severity_recall.png", dpi=120, bbox_inches="tight")
    plt.close(fig)


def plot_categorical_accuracy(summary, out_dir):
    cols = [f"{f}_acc" for f in CATEGORICAL_FIELDS]
    melted = summary[cols].melt(var_name="field", value_name="accuracy")
    melted["field"] = melted["field"].str.replace("_acc", "")
    fig, ax = plt.subplots(figsize=(10, 6))
    sns.boxplot(data=melted, x="field", y="accuracy", palette="Blues", ax=ax)
    sns.stripplot(data=melted, x="field", y="accuracy", color="black", alpha=0.3, size=3, ax=ax)
    ax.set_ylim(0, 1.05)
    ax.set_title("Accuracy de campos categóricos / numéricos (1 boxplot por campo, 129 PDFs)")
    fig.tight_layout()
    fig.savefig(out_dir / "04_categorical_accuracy.png", dpi=120, bbox_inches="tight")
    plt.close(fig)


def plot_text_rouge(summary, out_dir):
    cols = [f"{f}_rouge" for f in TEXT_FIELDS]
    melted = summary[cols].melt(var_name="field", value_name="rouge_l")
    melted["field"] = melted["field"].str.replace("_rouge", "")
    fig, ax = plt.subplots(figsize=(14, 6))
    sns.boxplot(data=melted, x="field", y="rouge_l", palette="Greens", ax=ax)
    sns.stripplot(data=melted, x="field", y="rouge_l", color="black", alpha=0.3, size=3, ax=ax)
    ax.set_ylim(0, 1.05)
    ax.set_title("ROUGE-L por campo texto (apenas both-filled, 129 PDFs)\nlog_method omitido: CSV nativo do OpenVAS não exporta esse campo")
    plt.xticks(rotation=20, ha="right")
    fig.tight_layout()
    fig.savefig(out_dir / "05_text_rouge.png", dpi=120, bbox_inches="tight")
    plt.close(fig)


def plot_top_bottom_f1(summary, out_dir):
    sorted_df = summary.sort_values("f1")
    bottom = sorted_df.head(15)
    top = sorted_df.tail(15)
    fig, axes = plt.subplots(1, 2, figsize=(18, 8))
    sns.barplot(data=bottom, y="pdf", x="f1", palette="Reds_r", ax=axes[0])
    axes[0].set_title("15 PDFs com pior F1")
    axes[0].set_xlim(0, 1.05)
    sns.barplot(data=top, y="pdf", x="f1", palette="Greens", ax=axes[1])
    axes[1].set_title("15 PDFs com melhor F1")
    axes[1].set_xlim(0, 1.05)
    fig.tight_layout()
    fig.savefig(out_dir / "06_top_bottom_f1.png", dpi=120, bbox_inches="tight")
    plt.close(fig)


def plot_pred_vs_baseline(summary, out_dir):
    fig, ax = plt.subplots(figsize=(10, 8))
    max_v = max(summary["n_baseline"].max(), summary["n_pred"].max()) + 5
    ax.plot([0, max_v], [0, max_v], "k--", alpha=0.3, label="igualdade")
    sns.scatterplot(
        data=summary, x="n_baseline", y="n_pred",
        hue="f1", palette="viridis", size="n_baseline",
        sizes=(30, 400), alpha=0.7, ax=ax,
    )
    ax.set_title("nº de vulnerabilidades — predito (LLM) vs baseline (CSV)")
    ax.set_xlabel("n_baseline")
    ax.set_ylabel("n_pred")
    fig.tight_layout()
    fig.savefig(out_dir / "07_pred_vs_baseline.png", dpi=120, bbox_inches="tight")
    plt.close(fig)


def plot_invented_vs_missing(errors, out_dir):
    counts = errors.groupby(["pdf", "kind"]).size().unstack(fill_value=0).reset_index()
    if "missing" not in counts.columns:
        counts["missing"] = 0
    if "invented" not in counts.columns:
        counts["invented"] = 0
    counts["total"] = counts["missing"] + counts["invented"]
    top = counts.sort_values("total", ascending=False).head(20)
    fig, ax = plt.subplots(figsize=(14, 8))
    top_sorted = top.sort_values("total")
    ax.barh(top_sorted["pdf"], top_sorted["missing"], color="#dc2626",
            label="missing (baseline tem, LLM não detectou)")
    ax.barh(top_sorted["pdf"], top_sorted["invented"], left=top_sorted["missing"],
            color="#3b82f6", label="invented (LLM achou, baseline não tem)")
    ax.set_title("Top 20 PDFs com mais erros (missing + invented)")
    ax.legend(loc="lower right")
    fig.tight_layout()
    fig.savefig(out_dir / "08_errors_top20.png", dpi=120, bbox_inches="tight")
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", default="evaluation_report.xlsx", type=Path)
    parser.add_argument("--output-dir", default="evaluation_charts", type=Path)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    summary = pd.read_excel(args.report, sheet_name="summary")
    agg_severity = pd.read_excel(args.report, sheet_name="aggregate_severity")
    errors = pd.read_excel(args.report, sheet_name="errors")

    plot_kpi_dashboard(summary, agg_severity, args.output_dir)
    plot_field_fidelity(summary, args.output_dir)
    plot_field_heatmap(summary, args.output_dir)
    plot_field_radar(summary, args.output_dir)
    plot_performance_curves(summary, args.output_dir)
    plot_ecdf(summary, args.output_dir)
    plot_pairplot(summary, args.output_dir)
    plot_prf_distribution(summary, args.output_dir)
    plot_pr_scatter(summary, args.output_dir)
    plot_severity_recall(agg_severity, args.output_dir)
    plot_categorical_accuracy(summary, args.output_dir)
    plot_text_rouge(summary, args.output_dir)
    plot_top_bottom_f1(summary, args.output_dir)
    plot_pred_vs_baseline(summary, args.output_dir)
    plot_invented_vs_missing(errors, args.output_dir)

    print(f"Charts written to {args.output_dir}/")


if __name__ == "__main__":
    main()
