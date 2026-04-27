"""
PNG chart generation for metrics.
Centralizes all matplotlib-based PNG generation functions.
"""

import os
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
from matplotlib.container import BarContainer
from matplotlib.lines import Line2D
from datetime import datetime
from typing import Dict

# Shared baseline patterns — used consistently across all PNG charts
BASELINE_PATTERNS = ['/', '+', '\\', '-', '|', '++', 'X', 'o', 'O', '.', '*', '//', '\\\\', '||', '--', 'XX', '..', '-\\']


def generate_similarity_pngs(stacked_data: Dict, output_dir: str = 'plot_runs') -> None:
    """
    Generate PNG charts for similarity category distribution separated by metric (BERT/ROUGE).
    Shows all baselines in one chart with different patterns (hatches).
    
    Args:
        stacked_data: Dict from collect_similarity_distribution() -> { metric: { baseline: { model: [...percentages] } } }
        output_dir: Directory to save PNG files
    """
    categories = ['Highly Similar', 'Moderately Similar', 'Slightly Similar', 'Divergent', 'Absent']
    colors = ['#185542', '#1543a5', '#e6a70a', '#a81e1e', '#d3d5d8']
    
    os.makedirs(output_dir, exist_ok=True)
    
    if not stacked_data:
        return
    
    # Iterate over metrics (bert, rouge)
    for metric, baseline_data in stacked_data.items():
        # Get all unique models across all baselines
        all_models = set()
        for baseline_dict in baseline_data.values():
            all_models.update(baseline_dict.keys())
        models = sorted(list(all_models))
        baselines = sorted(baseline_data.keys())
        
        n_models = len(models)
        n_baselines = len(baselines)
        
        if n_models == 0 or n_baselines == 0:
            continue
        
        # Setup figure
        fig, ax = plt.subplots(figsize=(18, 8))
        plt.rcParams.update({'font.size': 15})
        
        bar_width = 0.75 / n_baselines
        x = np.arange(n_models)
        
        # Draw bars for each baseline
        for b_idx, baseline in enumerate(baselines):
            models_dict = baseline_data[baseline]
            hatch_pattern = BASELINE_PATTERNS[b_idx % len(BASELINE_PATTERNS)]
            
            for m_idx, model in enumerate(models):
                # Get percentages for this model, or zeros if not present
                if model in models_dict:
                    percentages = models_dict[model]
                else:
                    percentages = [0.0] * len(categories)
                
                # Stack bars
                bottom = 0.0
                bar_x = x[m_idx] + b_idx * bar_width
                
                for cat_idx, (cat, color) in enumerate(zip(categories, colors)):
                    ax.bar(bar_x, percentages[cat_idx], bar_width, 
                          bottom=bottom, color=color, edgecolor='#cccccc', 
                          linewidth=0.7, hatch=hatch_pattern)
                    bottom += percentages[cat_idx]
        
        # Configure axes
        ax.set_ylabel('Distribution (%)', fontsize=18)
        ax.set_xlabel('Model', fontsize=18)
        ax.set_ylim(0, 100)
        ax.set_title(f'Similarity Category Distribution\n{metric.upper()}', fontsize=20, fontweight='bold')
        ax.set_xticks(x + bar_width * (n_baselines - 1) / 2)
        ax.set_xticklabels([m.capitalize() for m in models], fontsize=16)
        
        # Create legends
        category_patches = [Patch(facecolor=color, edgecolor='#cccccc', linewidth=0.7, label=cat)
                           for cat, color in zip(categories, colors)]
        baseline_patches = [Patch(facecolor='#cccccc', edgecolor='#333', hatch=BASELINE_PATTERNS[i % len(BASELINE_PATTERNS)], label=b)
                           for i, b in enumerate(baselines)]
        
        # Add legends
        legend1 = fig.legend(category_patches, [p.get_label() for p in category_patches],
                            loc='lower center', bbox_to_anchor=(0.5, 0.02), ncol=5,
                            fontsize=14, frameon=True, title='Category', title_fontsize=15)
        
        legend2 = fig.legend(baseline_patches, [p.get_label() for p in baseline_patches],
                            loc='lower center', bbox_to_anchor=(0.5, -0.08), 
                            ncol=min(n_baselines, 4), fontsize=14, frameon=True,
                            title='Baseline (pattern)', title_fontsize=15)
        
        plt.tight_layout(rect=[0, 0.12, 1, 1])
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        fname_out = os.path.join(output_dir, f'stacked_similarity_{metric}_{timestamp}.png')
        plt.savefig(fname_out, dpi=150, bbox_inches='tight')
        plt.close()
        print(f"  • PNG saved: {fname_out}")


def generate_matched_rate_png(matched_rate_data: Dict, recall_data: Dict = None, output_dir: str = 'plot_runs') -> None:
    """
    Generate PNG chart for matched rate and recall data side by side.
    Each model gets two adjacent bars (Matched Rate | Recall) with hatch patterns for baselines.
    
    Args:
        matched_rate_data: Dict from collect_matched_rate_data()
        recall_data: Dict from collect_recall_data() (optional)
        output_dir: Directory to save PNG files
    """
    os.makedirs(output_dir, exist_ok=True)
    
    if not matched_rate_data:
        return
    
    if recall_data is None:
        recall_data = {}
    
    # Get all unique models and baselines
    all_models = set()
    for baseline_dict in matched_rate_data.values():
        all_models.update(baseline_dict.keys())
    if recall_data:
        for baseline_dict in recall_data.values():
            all_models.update(baseline_dict.keys())
    
    models = sorted(list(all_models))
    baselines = sorted(matched_rate_data.keys())
    
    n_models = len(models)
    n_baselines = len(baselines)
    
    if n_models == 0 or n_baselines == 0:
        return
    
    # Setup figure
    fig, ax = plt.subplots(figsize=(14, 8))
    plt.rcParams.update({'font.size': 12})
    
    # Colors: Amarelo (precision) e Roxo (recall)
    COLOR_PRECISION = '#f59e0b'  # Amarelo
    COLOR_RECALL = '#7c3aed'     # Roxo
    
    bar_width = 0.35
    spacing = 2.5  # Space between model groups
    x_pos = 0
    x_ticks = []
    x_labels = []
    
    # Draw bars
    for model_idx, model in enumerate(models):
        x_model_start = x_pos
        
        for b_idx, baseline in enumerate(baselines):
            # Precision bar (Matched Rate)
            matched_val = matched_rate_data[baseline].get(model, {}).get('m', 0)
            matched_std = matched_rate_data[baseline].get(model, {}).get('s', 0)
            hatch = BASELINE_PATTERNS[b_idx % len(BASELINE_PATTERNS)]
            
            ax.bar(x_pos, matched_val, bar_width, yerr=matched_std,
                   color=COLOR_PRECISION, hatch=hatch, edgecolor='#333', linewidth=1.2,
                   capsize=5, error_kw={'linewidth': 1.5})
            x_pos += bar_width
            
            # Recall bar
            recall_val = recall_data.get(baseline, {}).get(model, {}).get('m', 0)
            recall_std = recall_data.get(baseline, {}).get(model, {}).get('s', 0)
            
            ax.bar(x_pos, recall_val, bar_width, yerr=recall_std,
                   color=COLOR_RECALL, hatch=hatch, edgecolor='#333', linewidth=1.2,
                   capsize=5, error_kw={'linewidth': 1.5})
            x_pos += bar_width
        
        # Position label at center of model group
        x_ticks.append((x_model_start + x_pos - bar_width) / 2)
        x_labels.append(model.capitalize())
        
        # Add spacing between models
        x_pos += spacing
    
    # Configure axes
    ax.set_ylabel('Percentage (%)', fontsize=14, fontweight='bold')
    ax.set_xlabel('Model', fontsize=14, fontweight='bold')
    ax.set_ylim(0, 105)
    ax.set_title('Precision & Recall — Accuracy & Coverage by Model', fontsize=16, fontweight='bold')
    ax.set_xticks(x_ticks)
    ax.set_xticklabels(x_labels, fontsize=12)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    
    # Create separate legends for colors (precision/recall) and patterns (baselines)
    from matplotlib.patches import Patch
    from matplotlib.lines import Line2D
    
    # Legend 1: Colors (Precision & Recall)
    color_elements = [
        Line2D([0], [0], color=COLOR_PRECISION, lw=8, label='Precision'),
        Line2D([0], [0], color=COLOR_RECALL, lw=8, label='Recall'),
    ]
    
    # Legend 2: Baseline patterns
    pattern_elements = [
        Patch(facecolor='gray', hatch=BASELINE_PATTERNS[b_idx % len(BASELINE_PATTERNS)], 
              edgecolor='#333', label=baseline)
        for b_idx, baseline in enumerate(baselines)
    ]
    
    # Add first legend (colors) at top
    legend1 = fig.legend(color_elements, ['Precision', 'Recall'],
                        loc='lower center', bbox_to_anchor=(0.5, 0.98), ncol=2,
                        fontsize=12, frameon=True, title='Metric', title_fontsize=13)
    
    # Add second legend (patterns) below the first
    legend2 = fig.legend(pattern_elements, baselines,
                        loc='lower center', bbox_to_anchor=(0.5, 0.92), 
                        ncol=min(len(baselines), 4), fontsize=11, frameon=True,
                        title='Baseline (pattern)', title_fontsize=12)
    
    plt.tight_layout(rect=[0, 0, 1, 0.96])
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    fname_out = os.path.join(output_dir, f'matched_rate_{timestamp}.png')
    plt.savefig(fname_out, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  • PNG saved: {fname_out}")


def generate_below_hs_pies_png(stacked_data: Dict, output_dir: str = 'plot_runs') -> None:
    """
    Generate PNG pie charts showing how each model contributes to scores below
    "Highly Similar", aggregated across all baselines and runs. Splits failures
    into two complementary types:
      - Quality issues (extracted but Moderately/Slightly/Divergent)
      - Recall issues  (Absent — not extracted at all)

    Output: two PNGs per metric (quality + absent), each summarizing performance
    over the full set of baselines. Per-baseline breakdowns remain accessible
    via the interactive HTML report.

    Aggregation: the per-model failure share is averaged across baselines where
    the model has data. Each baseline contributes equally regardless of size —
    a deliberate "consistency across scenarios" view; per-baseline detail lives
    in the HTML report.

    Args:
        stacked_data: { metric: { baseline: { model: [%HS, %Mod, %Sl, %Div, %Abs] } } }
        output_dir: Directory to save PNG files
    """
    if not stacked_data:
        return

    os.makedirs(output_dir, exist_ok=True)

    # Stable per-model color mapping so the same model uses the same color
    # across every pie generated in this run.
    model_color_palette = [
        '#0066CC', '#d85231', '#2ca02c', '#9467bd', '#ff7f0e',
        '#17becf', '#e377c2', '#bcbd22', '#8c564b', '#7f7f7f',
    ]
    all_models = sorted({m for bl in stacked_data.values() for d in bl.values() for m in d.keys()})
    color_by_model = {m: model_color_palette[i % len(model_color_palette)]
                      for i, m in enumerate(all_models)}

    kinds = [
        ('quality', 'Distribution of Scores Below Highly Similar', (1, 4)),  # Mod + Sl + Div
        ('absent',  'Distribution of Absent Vulnerabilities',      (4, 5)),  # Absent only
    ]

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    for metric, baseline_data in stacked_data.items():
        if not baseline_data:
            continue

        # Models present in at least one baseline for this metric
        models = sorted({m for d in baseline_data.values() for m in d.keys()})
        if not models:
            continue

        for kind_key, kind_label, (i_start, i_end) in kinds:
            # Average each model's failure share across baselines where it appears
            per_model = {}
            for m in models:
                model_values = [
                    sum(d[m][i_start:i_end])
                    for d in baseline_data.values()
                    if m in d
                ]
                if model_values:
                    per_model[m] = sum(model_values) / len(model_values)
                else:
                    per_model[m] = 0.0

            total = sum(per_model.values())
            if total <= 0:
                continue

            ordered_models = [m for m in models if per_model[m] > 0]
            shares = [per_model[m] / total * 100 for m in ordered_models]
            colors = [color_by_model[m] for m in ordered_models]

            fig, ax = plt.subplots(figsize=(10, 8))
            ax.pie(
                shares,
                labels=[m.capitalize() for m in ordered_models],
                colors=colors,
                autopct='%1.1f%%',
                startangle=90,
                pctdistance=0.75,
                textprops={'fontsize': 13},
                wedgeprops={'edgecolor': 'white', 'linewidth': 1.5},
            )
            ax.set_title(
                f'{kind_label}\n{metric.upper()} — All baselines (mean)',
                fontsize=15, fontweight='bold'
            )

            plt.tight_layout()
            fname_out = os.path.join(
                output_dir,
                f'below_hs_{kind_key}_{metric}_{timestamp}.png'
            )
            plt.savefig(fname_out, dpi=150, bbox_inches='tight')
            plt.close()
            print(f"  • PNG saved: {fname_out}")


def generate_absent_nonexistent_png(absent_nonexistent_data: Dict, output_dir: str = 'plot_runs') -> None:
    """
    Generate PNG chart for absent and non-existent vulnerability counts (STD).
    Shows standard deviation for both categories by model (aggregated across all baselines).

    Args:
        absent_nonexistent_data: Dict from collect_absent_nonexistent_data() -> { model: {'Absent': std, 'Non-existent': std} }
        output_dir: Directory to save PNG files
    """
    os.makedirs(output_dir, exist_ok=True)

    if not absent_nonexistent_data:
        return

    models = sorted(absent_nonexistent_data.keys())

    if len(models) == 0:
        return

    # Setup figure
    fig, ax = plt.subplots(figsize=(14, 8))
    plt.rcParams.update({'font.size': 15})

    bar_width = 0.35
    x = np.arange(len(models))

    # Colors for categories
    absent_color = '#d85231'      # Red
    nonexistent_color = '#0066CC'  # Blue

    absent_vals = []
    nonexistent_vals = []

    for model in models:
        absent_vals.append(absent_nonexistent_data[model].get('Absent', 0.0))
        nonexistent_vals.append(absent_nonexistent_data[model].get('Non-existent', 0.0))

    # Draw bars
    ax.bar(x - bar_width/2, absent_vals, bar_width,
           label='Absent', color=absent_color, edgecolor='#333', linewidth=1.2, alpha=0.85)

    ax.bar(x + bar_width/2, nonexistent_vals, bar_width,
           label='Non-existent', color=nonexistent_color, edgecolor='#333', linewidth=1.2, alpha=0.85)

    # Configure axes
    ax.set_ylabel('Standard Deviation', fontsize=18, fontweight='bold')
    ax.set_xlabel('LLM', fontsize=18, fontweight='bold')
    ax.set_title('Absent/Non-existent Std\n(Aggregated across all baselines)', fontsize=20, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels([m.capitalize() for m in models], fontsize=16)
    ax.legend(fontsize=14, loc='upper right')
    ax.grid(axis='y', alpha=0.3, linestyle='--')

    plt.tight_layout()

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    fname_out = os.path.join(output_dir, f'absent_nonexistent_std_{timestamp}.png')
    plt.savefig(fname_out, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  • PNG saved: {fname_out}")
