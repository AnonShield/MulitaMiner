import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from pathlib import Path

CATEGORY_COLORS = {
    "Highly Similar": "#059669",
    "Moderately Similar": "#0284c7",
    "Slightly Similar": "#d97706",
    "Divergent": "#dc2626",
    "Absent": "#d3d5d8"
}
PLOT_CATEGORY_ORDER = ["Highly Similar", "Moderately Similar", "Slightly Similar", "Divergent", "Absent"]


def create_score_heatmap(df_heatmap, metric_label: str, out_path: Path):
    if df_heatmap is None or df_heatmap.empty:
        print("❌ Nenhum dado disponível para heatmap!")
        return

    fig, ax = plt.subplots(figsize=(14, 6))
    sns.heatmap(df_heatmap, annot=True, fmt=".3f", cmap="RdYlGn",
                vmin=0, vmax=1, cbar_kws={"label": f"{metric_label} Score"},
                ax=ax, linewidths=0.5)

    title_base = "F1-Score by Field and Model"
    ax.set_title(f"{title_base} ({metric_label})", fontsize=14, fontweight='bold', pad=20)
    ax.set_xlabel("Fields", fontsize=12, fontweight='bold')
    ax.set_ylabel("Models", fontsize=12, fontweight='bold')

    plt.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path, dpi=300, bbox_inches='tight')
    print(f"Heatmap saved: {out_path}")
    plt.close()


def create_errors_comparison_chart(models_list, absent_counts, non_existent_counts, out_path: Path):
    if not models_list:
        print("❌ Nenhum dado disponível para Error Analysis!")
        return

    fig, ax = plt.subplots(figsize=(11, 6))
    x = np.arange(len(models_list))
    width = 0.35

    bars1 = ax.bar(x - width/2, absent_counts, width, label="Absent (Not Extracted)", color="#ef4444")
    bars2 = ax.bar(x + width/2, non_existent_counts, width, label="Non-existent (Invented)", color="#f59e0b")

    for bars in [bars1, bars2]:
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax.text(bar.get_x() + bar.get_width()/2, height,
                        f'{int(height)}', ha='center', va='bottom', fontsize=9, fontweight='bold')

    ax.set_ylabel("Quantity", fontsize=12, fontweight='bold')
    ax.set_title("Error Analysis of Vulnerability Extraction: Missing vs Invented Instances", 
                 fontsize=14, fontweight='bold', pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(models_list)
    ax.legend(fontsize=10)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    ax.set_axisbelow(True)

    plt.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path, dpi=300, bbox_inches='tight')
    print(f"✅ Error Analysis chart saved: {out_path}")
    plt.close()


def create_stacked_bar_chart(data, baseline_total, metric_label: str, out_path: Path):
    if not data:
        print("❌ No data available to plot!")
        return

    models = list(data.keys())
    category_data = {}
    for cat in PLOT_CATEGORY_ORDER:
        category_data[cat] = [data[model].get(cat, 0) for model in models]

    fig, ax = plt.subplots(figsize=(12, 7))
    x = np.arange(len(models))
    width = 0.6

    bottom = np.zeros(len(models))

    for cat in PLOT_CATEGORY_ORDER:
        values = category_data[cat]
        label = "Absent (Not Extracted)" if cat == "Absent" else cat
        ax.bar(x, values, width, label=label, bottom=bottom,
               color=CATEGORY_COLORS.get(cat, '#e5e7eb'), edgecolor='white', linewidth=1.5)
        bottom += values

    ax.set_ylabel('Number of Vulnerabilities', fontsize=12, fontweight='bold')
    ax.set_xlabel('LLM Models', fontsize=12, fontweight='bold')
    ax.set_title('Distribution of Similarity Levels in Vulnerability Extractions by LLMs', 
                 fontsize=14, fontweight='bold', pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels([m.upper().replace('GPT4.1', 'GPT-4.1').replace('GPT4', 'GPT-4')
                         .replace('LLAMA', 'LLaMA ') for m in models], fontsize=11)

    ax.set_ylim(0, baseline_total * 1.05)

    ax.axhline(y=baseline_total, color='#6b7280', linestyle='--', linewidth=1.5, 
               label=f'Baseline Total ({baseline_total})', alpha=0.6)

    ax.grid(axis='y', alpha=0.3, linestyle='--')
    ax.set_axisbelow(True)

    ax.legend(loc='center left', bbox_to_anchor=(1.02, 0.5), fontsize=10, framealpha=0.9)

    # Mostra número de pareadas (excluindo Absent) no topo da última categoria antes de Absent
    for i, model in enumerate(models):
        # Soma apenas as categorias de similaridade (exclui Absent)
        paired_count = sum(category_data[cat][i] for cat in PLOT_CATEGORY_ORDER if cat != "Absent")
        # Posição Y é no topo das pareadas (antes dos Absent)
        y_position = paired_count
        ax.text(i, y_position + baseline_total * 0.01, f'{paired_count}', 
                ha='center', va='bottom', fontsize=10, fontweight='bold')

    plt.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path_str = str(out_path)
    ax.set_title(f"Distribution of Similarity Levels in Vulnerability Extractions by LLMs ({metric_label})",
                 fontsize=14, fontweight='bold', pad=20)
    plt.savefig(out_path, dpi=300, bbox_inches='tight')
    print(f"✅ Similarity Comparison chart saved: {out_path}")
    plt.close()
