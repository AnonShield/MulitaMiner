from . import utils, charts
from pathlib import Path
import argparse
import sys


def main(baseline_file: str, baseline_sheet: str, models: list, metric_pref: str = None):
    metric = metric_pref
    if metric is None:
        # interactive prompt
        while metric not in ("rouge", "bert"):
            try:
                metric = input("Choose metric for plotting ('rouge' or 'bert'): ").strip().lower()
            except KeyboardInterrupt:
                print("\nInterrupted")
                return

    metric = metric.lower()

    # baseline_file can be just a filename placed under <repo_root>/baseline/
    repo_root = Path(__file__).parents[1]
    baseline_path = Path(baseline_file)
    if not baseline_path.is_absolute():
        # accept baseline name with or without extension; assume .xlsx by default
        if not Path(baseline_file).suffix:
            baseline_file_with_ext = f"{baseline_file}.xlsx"
        else:
            baseline_file_with_ext = baseline_file
        baseline_path = repo_root / "baselines" / baseline_file_with_ext

    if not baseline_path.exists():
        print(f"❌ Baseline file not found: {baseline_path}")
        return

    baseline_name = utils.sanitize_baseline_name(str(baseline_path))

    # Diretório de resultados específico da métrica e baseline
    results_dir = utils.get_results_dir(metric, str(baseline_path))
    print(f"Using results dir: {results_dir}")

    # 1) Heatmap
    print(f"\n📊 1/3: Generating Heatmap by Field ({metric.upper()})...")
    df_heatmap = utils.build_heatmap_df(metric, str(baseline_path), models)
    heatmap_out = results_dir / f"heatmap_scores_{metric}.png"
    charts.create_score_heatmap(df_heatmap, metric.upper(), heatmap_out)

    # 2) Error analysis (agnóstico)
    print(f"\n📊 2/3: Generating Error Analysis Chart (Absent vs Non-existent)...")
    models_list, absent_counts, non_existent_counts = utils.build_errors_data_anymetric(str(baseline_path), models)
    errors_out = results_dir / "chart_errors_comparison.png"
    charts.create_errors_comparison_chart(models_list, absent_counts, non_existent_counts, errors_out)

    # 3) Similarity stacked chart
    print(f"\n📊 3/3: Generating Similarity Comparison Chart ({metric.upper()})...")
    cat_data = utils.load_categorization_data(metric, str(baseline_path), models)
    if cat_data:
        baseline_total = utils.get_baseline_total(str(baseline_path), baseline_sheet)
        stacked_out = results_dir / f"similarity_comparison_chart_{metric}.png"
        charts.create_stacked_bar_chart(cat_data, baseline_total, metric.upper(), stacked_out)

    print("\n✅ ALL CHARTS GENERATED SUCCESSFULLY!")


def cli_entry():
    p = argparse.ArgumentParser(prog='plot')
    p.add_argument('--metric', choices=['rouge', 'bert'], help='Metric for plotting (rouge or bert)')
    p.add_argument('--baseline', required=False, help='Baseline file name inside baseline/ folder (e.g.: baseline.xlsx)')
    p.add_argument('--baseline-sheet', default='Vulnerabilities', help='Baseline sheet name')
    p.add_argument('--models', help='Comma-separated list of models (e.g.: deepseek,gpt4)')
    args = p.parse_args()


    # Se --models não for passado, lista todos os arquivos de resultado na pasta do baseline
    if args.models:
        models = [m.strip() for m in args.models.split(',') if m.strip()]
    else:
        # Busca todos os arquivos bert_comparison_*.xlsx e bert_comparison_vulnerabilities_*.xlsx na pasta do baseline
        metric = args.metric or 'bert'
        repo_root = Path(__file__).parents[1]
        baseline_path = Path(args.baseline)
        if not baseline_path.is_absolute():
            if not baseline_path.suffix:
                baseline_file_with_ext = f"{args.baseline}.xlsx"
            else:
                baseline_file_with_ext = args.baseline
            baseline_path = repo_root / "baselines" / baseline_file_with_ext
        results_dir = repo_root / metric / "results" / baseline_path.stem
        if results_dir.exists():
            models = []
            # Pega modelos dos dois padrões de arquivo
            for f in results_dir.glob(f"{metric}_comparison_*.xlsx"):
                nome = f.stem.replace(f"{metric}_comparison_", "")
                if nome.startswith("vulnerabilities_"):
                    nome = nome.replace("vulnerabilities_", "")
                models.append(nome)
            if not models:
                print(f"⚠️  No results found in {results_dir}")
        else:
            print(f"⚠️  Results folder not found: {results_dir}")
            models = []
        if not models:
            # fallback para lista padrão se nada encontrado
            models = ['deepseek', 'gpt4', 'gpt4.1', 'llama3', 'llama4']

    baseline = args.baseline
    if not baseline:
        baseline = input('Baseline file name (placed in ./baselines/) (extension optional): ').strip()
    # if user provided no extension, assume .xlsx
    if baseline and not Path(baseline).suffix:
        baseline = f"{baseline}.xlsx"

    main(baseline_file=baseline, baseline_sheet=args.baseline_sheet, models=models, metric_pref=args.metric)


if __name__ == '__main__':
    cli_entry()
