import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import re
import argparse
from datetime import datetime
from pathlib import Path
from matplotlib.patches import Patch

def plot_similarity_category_stacked_bar():
    """Generate stacked bar chart for similarity categories across metrics and scanners."""
    categories = [
        "Highly Similar",
        "Moderately Similar",
        "Slightly Similar",
        "Divergent",
        "Absent"
    ]
    colors = [
        "#185542",  # Highly Similar 
        "#1543a5",  # Moderately Similar 
        "#e6a70a",  # Slightly Similar 
        "#a81e1e",  # Divergent 
        "#d3d5d8"   # Absent 
    ]

    metrics = ["bert", "rouge"]
    os.makedirs('plot_runs', exist_ok=True)

    results_base = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'results_runs'))

    for metric in metrics:
        print(f"[STACKED] Processing metric: {metric}")
        data = {}
        for root, dirs, files in os.walk(results_base):
            for fname in files:
                if not (fname.startswith(f"{metric}_comparison_vulnerabilities_") and fname.endswith(".xlsx")):
                    continue
                fpath = os.path.join(root, fname)
                parts = fpath.replace('\\', '/').split('/')
                try:
                    folder_name = parts[-4]  
                    folder_lower = folder_name.lower()
                    if folder_lower.startswith('openvas'):
                        scanner = 'openvas'
                        baseline = folder_name[7:].lstrip('_')  
                    elif folder_lower.startswith('tenable'):
                        scanner = 'tenable'
                        baseline = folder_name[7:].lstrip('_')  
                    else:
                        scanner = folder_name
                        baseline = folder_name
                except Exception:
                    scanner = 'unknown'
                    baseline = 'unknown'
                scanner = scanner.lower()
                baseline = baseline.lower()
                llm = extract_llm_from_filename(fname)
                if llm is None:
                    continue
                try:
                    df = pd.read_excel(fpath, sheet_name="Categorization")
                except Exception as e:
                    print(f"Error reading {fpath}: {e}")
                    continue
                if "Category" not in df.columns:
                    print(f"Column 'Category' not found in {fpath}")
                    continue
                cat_counts = df["Category"].value_counts().to_dict()
                data\
                    .setdefault(scanner, {})\
                    .setdefault(baseline, {})\
                    .setdefault(llm, [])\
                    .append(cat_counts)

        for scanner, baselines_dict in data.items():
            baselines = sorted(baselines_dict.keys())
            llms = sorted(set(
                llm for bl in baselines_dict.values() for llm in bl.keys()
            ))

            if not llms or not baselines:
                continue

            n_llms = len(llms)
            n_baselines = len(baselines)
            bar_width = 0.75 / n_baselines
            x = np.arange(n_llms)

            fig, ax = plt.subplots(figsize=(18, 8))
            plt.rcParams.update({'font.size': 15})

            baseline_hatches = ['/', '+', '\\', '-', '|', '++', 'X', 'o', 'O', '.', '*', '//', '\\\\', '||', '--', 'XX', '..', '-\\']
            while len(baseline_hatches) < len(baselines):
                baseline_hatches *= 2

            for b_idx, baseline in enumerate(baselines):
                llm_dict = baselines_dict[baseline]
                hatch_pattern = baseline_hatches[b_idx]

                for l_idx, llm in enumerate(llms):
                    runs = llm_dict.get(llm, [])

                    if not runs:
                        pct = [0.0] * len(categories)
                    else:
                        avg_counts = {}
                        for run in runs:
                            for cat in categories + ["Non-existent"]:
                                avg_counts[cat] = avg_counts.get(cat, 0) + run.get(cat, 0)
                        avg_counts = {k: v / len(runs) for k, v in avg_counts.items()}
                        total = sum(avg_counts.get(cat, 0) for cat in categories)
                        if total == 0:
                            pct = [0.0] * len(categories)
                        else:
                            pct = [avg_counts.get(cat, 0) / total * 100 for cat in categories]

                    bottom = 0.0
                    bar_x = x[l_idx] + b_idx * bar_width

                    for cat_idx, (cat, color) in enumerate(zip(categories, colors)):
                        ax.bar(
                            bar_x, pct[cat_idx],
                            bottom=bottom,
                            color=color,
                            width=bar_width,
                            edgecolor="#cccccc",
                            linewidth=0.7,
                            hatch=hatch_pattern
                        )
                        bottom += pct[cat_idx]

            ax.set_ylabel("Distribution (%)", fontsize=18)
            ax.set_xlabel("LLM", fontsize=18)
            ax.set_ylim(0, 100)
            ax.set_title(
                f"Similarity Category Distribution\n{scanner} | {metric.upper()}",
                fontsize=20
            )
            ax.set_xticks(x + bar_width * (n_baselines - 1) / 2)
            ax.set_xticklabels(llms, fontsize=16)

            category_legend_patches = [
                Patch(facecolor=color, edgecolor="#cccccc", linewidth=0.7, label=cat)
                for cat, color in zip(categories, colors)
            ]
            
            baseline_legend_patches = [
                Patch(facecolor='#cccccc', edgecolor='#333', hatch=baseline_hatches[i], label=b)
                for i, b in enumerate(baselines)
            ]
            
            all_handles = category_legend_patches + baseline_legend_patches
            all_labels = [h.get_label() for h in all_handles]
            
            legend1 = fig.legend(
                handles=category_legend_patches,
                loc="lower center",
                bbox_to_anchor=(0.5, 0.02),
                ncol=5,
                fontsize=14,
                frameon=True,
                title="Category",
                title_fontsize=15
            )
            
            legend2 = fig.legend(
                handles=baseline_legend_patches,
                loc="lower center",
                bbox_to_anchor=(0.5, -0.08),
                ncol=min(len(baselines), 4),
                fontsize=14,
                frameon=True,
                title="Baseline (pattern)",
                title_fontsize=15
            )

            plt.tight_layout(rect=[0, 0.12, 1, 1])
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            fname_out = f"plot_runs/stacked_similarity_{scanner}_{metric}_{timestamp}.png"
            plt.savefig(fname_out, dpi=150, bbox_inches='tight')
            plt.close()
            print(f"Saved: {fname_out}")


def build_heatmap_df_all_llms(metric: str, baseline: str) -> pd.DataFrame:
    """Build heatmap dataframe aggregating scores across all LLMs for a metric and baseline."""
    metric = metric.lower()
    results_dir = Path('results_runs') / str(baseline)
    arquivos = []
    for root, dirs, files in os.walk(results_dir):
        for f in files:
            if (
                f.endswith(f"{metric}_comparison_vulnerabilities_"+f.split(f"{metric}_comparison_vulnerabilities_")[-1]) or
                f.endswith(f"{metric}_comparison_"+f.split(f"{metric}_comparison_")[-1])
            ):
                arquivos.append(os.path.join(root, f))
    if not arquivos:
        print(f"⚠️  No comparison files found in {results_dir} for heatmap.")
        return pd.DataFrame()
    data = {}  
    for arq in arquivos:
        llm = extract_llm_from_filename(os.path.basename(arq))
        if llm is None:
            continue
        try:
            df = pd.read_excel(arq, sheet_name="Summary")
        except Exception as e:
            print(f"❌ Error reading {arq}: {e}")
            continue
        for _, row in df.iterrows():
            col = row["Column"]
            if metric == 'rouge':
                score = row.get("Avg_ROUGE_L", None)
            else:
                score = row.get("Avg_BERTScore_F1", None)
            try:
                score = float(score) if score == score else 0.0
            except Exception:
                score = 0.0
            data.setdefault(llm, {}).setdefault(col, []).append(score)
    df_final = {}
    for llm, campos in data.items():
        df_final[llm] = {campo: (sum(scores)/len(scores) if scores else 0.0) for campo, scores in campos.items()}
    if not df_final:
        return pd.DataFrame()
    return pd.DataFrame(df_final).T


RESULTS_DIR = "results_runs"

def get_baselines():
    """Get list of baselines from results_runs directory."""
    return sorted([d for d in os.listdir(RESULTS_DIR) if os.path.isdir(os.path.join(RESULTS_DIR, d))])


SUMMARY_PATTERN = re.compile(r"(?P<baseline>.+)_(?P<scanner>.+)\.xlsx")
LLMS = ["deepseek", "gpt4", "gpt5", "llama3", "llama4"]
SCORE_FIELDS = ["score", "rouge", "bert", "bleu", "f1", "precision", "recall"]


def extract_scanner_and_report(filename):
    """Extract scanner and baseline report name from filename."""
    base = os.path.splitext(filename)[0]
    parts = base.split('_')
    scanner = None
    report = None
    for i, part in enumerate(parts):
        if part.lower() in ["openvas", "tenable"]:
            scanner = part
            for j in range(i+1, len(parts)):
                candidate = parts[j]
                if candidate.lower() not in ["bert", "rouge"] and candidate.lower() not in LLMS:
                    report = candidate
                    break
            break
    return scanner, report

def extract_llm_from_filename(filename):
    """Extract LLM name from filename."""
    base = os.path.splitext(filename)[0]
    parts = base.split('_')
    for part in reversed(parts):
        if part.lower() in LLMS:
            return part.lower()
    return None


def extract_run_from_path(path):
    """Extract run number from file path."""
    m = re.search(r"run(\d+)", path)
    if m:
        return int(m.group(1))
    return None

# =====================
# PLOTS PRINCIPAIS
# =====================
def plot_absent_nonexistent_mean():
    """Generate plots for absent and non-existent vulnerability counts."""
    absent_nonexistent_data = []
    file_count = 0
    row_count = 0
    arquivos_encontrados = False
    os.makedirs('plot_runs', exist_ok=True)
    for root, dirs, files in os.walk(RESULTS_DIR):
        for fname in files:
            if not fname.endswith(".xlsx"):
                continue
            arquivos_encontrados = True
            scanner, report = extract_scanner_and_report(fname)
            path = os.path.join(root, fname)
            run_num = extract_run_from_path(path)
            try:
                df = pd.read_excel(path)
            except Exception as e:
                print(f"Error reading {fname}: {e}")
                continue
            absent_col = None
            nonexistent_col = None
            for c in df.columns:
                if c.lower() in ["absent", "absent_count"]:
                    absent_col = c
                if c.lower() in ["invented", "nonexistent_count", "non-existent", "non_existent_count"]:
                    nonexistent_col = c
            if absent_col is None or nonexistent_col is None:
                continue
            llm_name = extract_llm_from_filename(fname)
            if llm_name is None:
                llm_name = "unknown"
            for _, row in df.iterrows():
                row_count += 1
                absent_nonexistent_data.append({
                    "scanner": scanner,
                    "report": report,
                    "llm": llm_name,
                    "run_num": run_num,
                    "Absent": row[absent_col],
                    "Non-existent": row[nonexistent_col]
                })
    if not arquivos_encontrados:
        print(f"[ABSENT/NON-EXISTENT] No .xlsx files found in {RESULTS_DIR}. Please check the directory structure.")
    if absent_nonexistent_data:
        df = pd.DataFrame(absent_nonexistent_data)
        combos = df.groupby(["scanner", "report"]).size().index
        for scanner, report in combos:
            print(f"Generating Absent/Non-existent std barplot for {scanner} | {report}...")
            df_sub = df[(df["scanner"]==scanner) & (df["report"]==report)]
            bar_data = df_sub.groupby(["llm"])[["Absent", "Non-existent"]].std().reset_index()
            plt.figure(figsize=(18, 8))
            plt.rcParams.update({'font.size': 15})
            x = np.arange(len(bar_data["llm"]))
            width = 0.35
            plt.bar(x - width/2, bar_data["Absent"], width=width, label="Absent", color="#d85231")
            plt.bar(x + width/2, bar_data["Non-existent"], width=width, label="Non-existent", color="#151529")
            plt.title(f"Absent/Non-existent Std\n{scanner} | {report}", fontsize=20)
            plt.xlabel("LLM", fontsize=18)
            plt.ylabel("Standard Deviation", fontsize=18)
            plt.xticks(x, bar_data["llm"], rotation=0, fontsize=16)
            plt.legend(fontsize=14)
            plt.tight_layout()
            from datetime import datetime
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            plt.savefig(f"plot_runs/absent_nonexistent_std_{scanner}_{report}_{timestamp}.png")
            plt.close()
        print(f"[ABSENT/NON-EXISTENT] Graphs saved in plot_runs/ for each scanner+report.")
    else:
        print("[ABSENT/NON-EXISTENT] No valid data found to generate barplots for Absent/Non-existent.")


def plot_matched_rate_mean_std():
    """Generate plots for matched rate mean and standard deviation across runs."""
    baselines = get_baselines()
    arquivos_processados = []
    matched_data = []
    arquivos_encontrados = False
    os.makedirs('plot_runs', exist_ok=True)
    def normalize_name(name):
        """Normalize names for comparison."""
        return str(name).strip().lower().replace(' ', '').replace('_', '').replace('-', '')
    for root, dirs, files in os.walk(RESULTS_DIR):
        for fname in files:
            if not fname.endswith(".xlsx"):
                continue
            arquivos_encontrados = True
            scanner, report = extract_scanner_and_report(fname)
            scanner_norm = normalize_name(scanner)
            report_norm = normalize_name(report)
            path = os.path.join(root, fname)
            run_num = extract_run_from_path(path)
            try:
                df = pd.read_excel(path)
                arquivos_processados.append((fname, list(df.columns)))
            except Exception as e:
                print(f"Error reading {fname}: {e}")
                continue
            matched_col = None
            for c in df.columns:
                if c.lower() in ["matched_rate", "matchedrate", "matched", "match_rate", "match_rate"]:
                    matched_col = c
                    break
            if matched_col is None:
                continue
            llm_name = extract_llm_from_filename(fname)
            if llm_name is None:
                llm_name = "unknown"
            metric = None
            for m in ["bert", "rouge"]:
                if m in fname.lower():
                    metric = m
                    break
            if metric is None:
                metric = "unknown"
            for _, row in df.iterrows():
                matched_data.append({
                    "scanner": scanner_norm,
                    "report": report_norm,
                    "llm": llm_name,
                    "run_num": run_num,
                    "Matched_Rate": row[matched_col],
                    "metric": metric
                })
    
    if not arquivos_encontrados:
        print(f"[MATCHED RATE] No .xlsx files found in {RESULTS_DIR}. Please check the directory structure.")
    if matched_data:
        df_matched = pd.DataFrame(matched_data)
        scanners = sorted(df_matched["scanner"].unique())
        metrics = ["bert", "rouge"]
        colors = [
            "#1f7067",  
            "#d85231",  
            "#4c2b63",  
            "#1A353F",  
            "#1b5d86",  
            "#151529"   
        ]
        expected_baselines = [normalize_name(b) for b in baselines]
        for scanner in scanners:
            for metric in metrics:
                df_s = df_matched[(df_matched["scanner"]==scanner) & (df_matched["metric"]==metric)]
                if df_s.empty:
                    continue
                baselines_present = sorted([normalize_name(b) for b in df_s["report"].unique()])
                if not baselines_present:
                    print(f"No baselines found for {scanner} | {metric}, skipping plot.")
                    continue

                llms = sorted(df_s["llm"].unique())
                x = np.arange(len(llms))
                width = 0.8 / max(1, len(baselines_present))
                plt.figure(figsize=(18, 8))
                plt.rcParams.update({'font.size': 15})
                for idx, baseline in enumerate(baselines_present):
                    df_b = df_s[df_s["report"].apply(normalize_name)==baseline]
                    means = df_b.groupby("llm")["Matched_Rate"].mean().reindex(llms, fill_value=0)
                    stds = df_b.groupby("llm")["Matched_Rate"].std().reindex(llms, fill_value=0)
                    plt.bar(x + idx*width, means, width=width, yerr=stds, label=baseline, color=colors[idx % len(colors)], alpha=0.8)
                    main_title = "Matched Rate Mean ± Std (%)"
                    subtitle = f"{scanner} | {metric}"
                    plt.title(f"{main_title}\n{subtitle}", fontsize=20)
                plt.xlabel("LLM", fontsize=18)
                plt.ylabel("Matched Rate (%)", fontsize=18)
                plt.xticks(x + width*(len(baselines_present)-1)/2, llms, fontsize=16)
                plt.legend(title="Baseline", fontsize=14)
                plt.tight_layout()
                from datetime import datetime
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                plt.savefig(f"plot_runs/matched_rate_mean_std_{scanner}_{metric}_{timestamp}.png")
                plt.close()
        print(f"[MATCHED RATE] Graphs saved in plot_runs/ for each scanner+metric.")
    else:
        print("[MATCHED RATE] No valid data found to generate barplots for Matched Rate.")

# ========== HEATMAPS DE SCORES ==========
def plot_score_heatmaps():
    """Generate heatmaps of evaluation scores for different baselines and metrics."""
    import importlib.util
    import sys
    import os
    import re
   
    charts_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../metrics/plot/charts.py'))
    utils_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../metrics/plot/utils.py'))

    spec_charts = importlib.util.spec_from_file_location("charts", charts_path)
    charts = importlib.util.module_from_spec(spec_charts)
    sys.modules["charts"] = charts
    spec_charts.loader.exec_module(charts)
    spec_utils = importlib.util.spec_from_file_location("utils", utils_path)
    utils = importlib.util.module_from_spec(spec_utils)
    sys.modules["utils"] = utils
    spec_utils.loader.exec_module(utils)
    
    baselines = get_baselines()
    metrics = ["bert", "rouge"]
    import datetime
    os.makedirs('plot_runs', exist_ok=True)
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    for baseline in baselines:
        if '_' in baseline:
            scanner, base = baseline.split('_', 1)
        else:
            scanner, base = baseline, ''
        for metric in metrics:
            print(f"[HEATMAP] Generating heatmap for baseline={baseline}, metric={metric}")
            try:
                df_heatmap = build_heatmap_df_all_llms(metric, baseline)
                if df_heatmap is None or df_heatmap.empty:
                    print(f"[HEATMAP] No data available for heatmap!")
                    continue
                from pathlib import Path
                import matplotlib.pyplot as plt
                out_path = Path('plot_runs') / f"heatmap_scores_{baseline}_{metric}_{timestamp}.png"
                plt.figure(figsize=(18, 8))
                plt.rcParams.update({'font.size': 15})
                import seaborn as sns
                ax = sns.heatmap(
                    df_heatmap, annot=True, fmt=".3f", cmap="RdYlGn", vmin=0, vmax=1,
                    cbar_kws={"label": f"{metric.upper()} Score"}, linewidths=0.5,
                    annot_kws={"fontsize": 14}
                )
                main_title = "Score Heatmap"
                subtitle = f"{scanner} | {base} | {metric}"
                plt.title(f"{main_title}\n{subtitle}", fontsize=22, fontweight='normal', pad=24)
                plt.xlabel("Fields", fontsize=20, labelpad=12)
                plt.ylabel("Models", fontsize=20, labelpad=12)
                plt.xticks(fontsize=16, rotation=30, ha='right')
                plt.yticks(fontsize=16)
                plt.tight_layout(rect=[0, 0, 1, 0.97])
                plt.savefig(out_path, dpi=300, bbox_inches='tight')
                plt.close()
                print(f"Heatmap saved: {out_path}")
            except Exception as e:
                print(f"[HEATMAP] Error generating heatmap for baseline={baseline}, metric={metric}: {e}")


if __name__ == "__main__":
    plot_absent_nonexistent_mean()
    plot_matched_rate_mean_std()
    plot_score_heatmaps()
    plot_similarity_category_stacked_bar()
