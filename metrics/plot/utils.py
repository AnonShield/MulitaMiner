import pandas as pd
from pathlib import Path
import re


def sanitize_baseline_name(baseline_file: str) -> str:
    p = Path(baseline_file)
    name = p.stem
    # replace spaces and problematic chars
    name = re.sub(r"\s+", "_", name)
    name = re.sub(r"[^0-9A-Za-z_\-\.]+", "", name)
    return name


def get_results_dir(metric: str, baseline_file: str) -> Path:
    metric = metric.lower()
    root = Path(__file__).parents[1] / metric / "results"
    # If baseline_file is a path, use its stem; otherwise use provided string
    b = Path(baseline_file).stem if Path(baseline_file).name else str(baseline_file)

    # Normalize helper: remove non-alnum to compare flexibly
    def _norm(s: str) -> str:
        import re
        return re.sub(r"[^0-9a-z]", "", s.lower())

    target_norm = _norm(b)

    # If a matching folder already exists under results (case-insensitive, ignoring punctuation), prefer it
    if root.exists():
        for child in root.iterdir():
            if child.is_dir():
                if _norm(child.name) == target_norm:
                    return child

    # Fallback: construct sanitized path (may not exist yet)
    base = root / sanitize_baseline_name(baseline_file)
    return base


def build_heatmap_df(metric: str, baseline_file: str, models: list) -> pd.DataFrame:
    metric = metric.lower()
    results_dir = get_results_dir(metric, baseline_file)
    data = {}

    for model in models:
        file_candidates = [
            results_dir / f"{metric}_comparison_{model}.xlsx",
            results_dir / f"{metric}_comparison_vulnerabilities_{model}.xlsx"
        ]
        file_path = None
        for candidate in file_candidates:
            if candidate.exists():
                file_path = candidate
                break
        if not file_path:
            print(f"⚠️  {model}: File not found: {file_candidates}")
            continue
        try:
            df = pd.read_excel(file_path, sheet_name="Summary")
            scores = {}
            for _, row in df.iterrows():
                col_name = row["Column"]
                if metric == 'rouge':
                    avg_score = row.get("Avg_ROUGE_L", None)
                else:
                    avg_score = row.get("Avg_BERTScore_F1", None)
                try:
                    avg_score = float(avg_score) if avg_score == avg_score else 0.0
                except Exception:
                    avg_score = 0.0
                scores[col_name] = avg_score
            data[model] = scores
        except Exception as e:
            print(f"❌ Error processing {model}: {e}")
            continue

    if not data:
        return pd.DataFrame()

    df_heatmap = pd.DataFrame(data).T
    return df_heatmap


def build_errors_data_anymetric(baseline_file: str, models: list) -> tuple:
    """Retorna (models_list, absent_counts, non_existent_counts)
    procurando em rouge/results/<baseline> e bert/results/<baseline> e preferindo
    primeiro o arquivo da métrica passada ao plot CLI.
    """
    # This util will be called by CLI with metric context; here we simply try both folders
    models_list = []
    absent_counts = []
    non_existent_counts = []

    # Prefer to look inside each metric folder for a matching results dir; if neither exists, skip
    for model in models:
        # try rouge then bert, but use get_results_dir to respect existing folder variants
        rouge_dir = get_results_dir('rouge', baseline_file)
        bert_dir = get_results_dir('bert', baseline_file)
        file_candidates = [
            rouge_dir / f"rouge_comparison_{model}.xlsx",
            rouge_dir / f"rouge_comparison_vulnerabilities_{model}.xlsx",
            bert_dir / f"bert_comparison_{model}.xlsx",
            bert_dir / f"bert_comparison_vulnerabilities_{model}.xlsx"
        ]
        found = None
        for c in file_candidates:
            if c.exists():
                found = c
                break
        if not found:
            print(f"⚠️  {model}: no file found among {file_candidates}")
            continue
        try:
            df = pd.read_excel(found, sheet_name="Categorization")
            absent = len(df[df["Category"] == "Absent"]) if "Category" in df.columns else 0
            non_existent = len(df[df["Category"] == "Non-existent"]) if "Category" in df.columns else 0
            models_list.append(model.upper().replace('GPT4.1', 'GPT-4.1').replace('GPT4', 'GPT-4'))
            absent_counts.append(absent)
            non_existent_counts.append(non_existent)
        except Exception as e:
            print(f"❌ Error processing {model}: {e}")
            continue

    return models_list, absent_counts, non_existent_counts


def load_categorization_data(metric: str, baseline_file: str, models: list) -> dict:
    data = {}
    metric = metric.lower()
    results_dir = get_results_dir(metric, baseline_file)

    for model in models:
        file_candidates = [
            results_dir / f"{metric}_comparison_{model}.xlsx",
            results_dir / f"{metric}_comparison_vulnerabilities_{model}.xlsx"
        ]
        file_path = None
        for candidate in file_candidates:
            if candidate.exists():
                file_path = candidate
                break
        if not file_path:
            print(f"⚠️  File not found: {file_candidates}")
            continue
        try:
            df = pd.read_excel(file_path, sheet_name="Categorization")
            map_df = pd.read_excel(file_path, sheet_name="Mapping_Debug")
            map_df = map_df[map_df["Status"] == "MATCHED"]
            mapping = dict(zip(map_df["Extraction_Name"], map_df["Baseline_Name_matched"]))

            rank = {"Highly Similar": 4, "Moderately Similar": 3, "Slightly Similar": 2, "Divergent": 1}
            
            # Counts ALL matched instances, not just unique baseline
            category_counts = {cat: 0 for cat in ["Highly Similar", "Moderately Similar", "Slightly Similar", "Divergent"]}
            
            matched_rows = df[df["Type"].str.contains("Matched", na=False)]
            for _, r in matched_rows.iterrows():
                cat = r["Category"]
                if cat in category_counts:
                    category_counts[cat] += 1

            absent_count = len(df[df["Category"] == "Absent"]) if "Category" in df.columns else 0
            category_counts["Absent"] = absent_count

            data[model] = category_counts
            total_sim_and_absent = sum(category_counts.values())
            print(f"✅ {model}: {total_sim_and_absent} vulnerabilities categorized (Absent={absent_count})")

        except Exception as e:
            print(f"❌ Error processing {model}: {e}")
            continue

    return data


def get_baseline_total(baseline_file: str, baseline_sheet: str) -> int:
    try:
        df = pd.read_excel(baseline_file, sheet_name=baseline_sheet)
        total = len(df)
        print(f"\n📊 Total vulnerabilities in baseline: {total}")
        return total
    except Exception as e:
        print(f"❌ Error reading baseline: {e}")
        return 100
