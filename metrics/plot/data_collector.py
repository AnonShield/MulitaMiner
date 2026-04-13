"""
Data collection module for metrics generation.
Collects metrics data from results_runs directory.
Uses field categories from common.field_mapper for deterministic/semantic field separation.
"""

import os
import re
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, List, Tuple, Optional

from metrics.common.field_mapper import load_field_categories


# ============= UTILITY FUNCTIONS =============
def discover_available_models(results_dir: str = "results_runs") -> List[str]:
    """
    Discover available models dynamically from directory structure.
    Only includes models that have actual data files (not empty directories).
    Returns sorted list of unique model names with valid data.
    """
    models = set()
    results_path = Path(results_dir)
    
    if not results_path.exists():
        return []
    
    # Iterate through baseline directories
    for baseline_dir in results_path.iterdir():
        if not baseline_dir.is_dir():
            continue
        
        # Each subdirectory under baseline is a model name
        for model_dir in baseline_dir.iterdir():
            if not model_dir.is_dir():
                continue
            
            # Check if this model directory has any actual data files
            has_data = False
            for root, dirs, files in os.walk(model_dir):
                for fname in files:
                    # Look for any meaningful data files (comparison files or JSON results)
                    if (fname.endswith(('.xlsx', '.json')) and 
                        any(x in fname.lower() for x in ['comparison', 'metrics', 'results'])):
                        has_data = True
                        break
                if has_data:
                    break
            
            # Only add model if it has data
            if has_data:
                models.add(model_dir.name)
    
    return sorted(list(models))


def extract_llm_from_filename(filename: str, available_models: List[str]) -> Optional[str]:
    """Extract LLM name from filename using available models list."""
    base = os.path.splitext(filename)[0]
    parts = base.split('_')
    for part in reversed(parts):
        if part.lower() in available_models:
            return part.lower()
    return None


def extract_run_number(path: str) -> Optional[int]:
    """Extract run number from path."""
    match = re.search(r'run(\d+)', path)
    return int(match.group(1)) if match else None


# ============= DATA COLLECTION FUNCTIONS =============
def collect_bert_rouge_data(available_models: List[str], results_dir: str = "results_runs") -> Tuple[Dict, Dict]:
    """
    Collect BERT & ROUGE data in Chart.js format.
    Uses semantic fields from field_categories.json configuration.
    Aggregates across multiple runs: sums values, then divides by number of runs to get average.
    
    Returns: (bert_data, rouge_data)
    Structure: { baseline: { model: { m: [...means], s: [...stds] } } }
    """
    bert_data = {}
    rouge_data = {}
    
    # Load semantic fields from config
    config = load_field_categories()
    semantic_fields = config.get('semantic', [])
    
    results_path = Path(results_dir)
    if not results_path.exists():
        return bert_data, rouge_data
    
    # First pass: collect all runs by (baseline, model, metric_type)
    bert_runs = {}  # (baseline, model) -> [{field_means}, {field_means}, ...]
    rouge_runs = {}  # (baseline, model) -> [{field_means}, {field_means}, ...]
    
    for baseline_dir in results_path.iterdir():
        if not baseline_dir.is_dir():
            continue
        
        baseline = baseline_dir.name
        
        for root, dirs, files in os.walk(baseline_dir):
            for fname in files:
                if not fname.endswith('.xlsx') or 'comparison' not in fname.lower():
                    continue
                
                llm = extract_llm_from_filename(fname, available_models)
                if not llm:
                    continue
                
                try:
                    excel_file = os.path.join(root, fname)
                    
                    if 'bert_comparison' in fname.lower():
                        df = pd.read_excel(excel_file, sheet_name='Summary')
                        means = []
                        stds = []
                        for field in semantic_fields:
                            mean_val = df[df['Column'] == field]['Avg_BERTScore_F1'].values
                            std_val = df[df['Column'] == field]['Std_BERTScore_F1'].values
                            means.append(float(mean_val[0]) if len(mean_val) > 0 else 0.0)
                            stds.append(float(std_val[0]) if len(std_val) > 0 else 0.0)
                        
                        key = (baseline, llm)
                        if key not in bert_runs:
                            bert_runs[key] = []
                        bert_runs[key].append({'m': means, 's': stds})
                    
                    elif 'rouge_comparison' in fname.lower():
                        df = pd.read_excel(excel_file, sheet_name='Summary')
                        means = []
                        stds = []
                        for field in semantic_fields:
                            mean_val = df[df['Column'] == field]['Avg_ROUGE_L'].values
                            std_val = df[df['Column'] == field]['Std_ROUGE_L'].values
                            means.append(float(mean_val[0]) if len(mean_val) > 0 else 0.0)
                            stds.append(float(std_val[0]) if len(std_val) > 0 else 0.0)
                        
                        key = (baseline, llm)
                        if key not in rouge_runs:
                            rouge_runs[key] = []
                        rouge_runs[key].append({'m': means, 's': stds})
                except Exception as e:
                    continue
    
    # Second pass: aggregate runs - average means, average stds
    for (baseline, llm), run_list in bert_runs.items():
        if baseline not in bert_data:
            bert_data[baseline] = {}
        
        # Average the means and stds across runs
        avg_means = list(np.mean([run['m'] for run in run_list], axis=0))
        avg_stds = list(np.mean([run['s'] for run in run_list], axis=0))
        bert_data[baseline][llm] = {'m': avg_means, 's': avg_stds}
    
    for (baseline, llm), run_list in rouge_runs.items():
        if baseline not in rouge_data:
            rouge_data[baseline] = {}
        
        # Average the means and stds across runs
        avg_means = list(np.mean([run['m'] for run in run_list], axis=0))
        avg_stds = list(np.mean([run['s'] for run in run_list], axis=0))
        rouge_data[baseline][llm] = {'m': avg_means, 's': avg_stds}
    
    return bert_data, rouge_data


def collect_deterministic_data(available_models: List[str], results_dir: str = "results_runs") -> Dict:
    """
    Collect deterministic field metrics (F1, Precision, Recall).
    Uses deterministic fields from field_categories.json configuration.
    
    Returns: { baseline: { model: { field: { f1/prec/rec: {m, s} } } } }
    """
    det_data = {}
    
    # Load deterministic fields from config
    config = load_field_categories()
    det_fields = config.get('deterministic', [])
    
    results_path = Path(results_dir)
    if not results_path.exists():
        return det_data
    
    # First pass: collect all runs by (baseline, llm)
    runs_data = {}  # (baseline, llm) -> {field: {f1: [...], prec: [...], rec: [...]}}
    
    for baseline_dir in results_path.iterdir():
        if not baseline_dir.is_dir():
            continue
        
        baseline = baseline_dir.name
        
        for root, dirs, files in os.walk(baseline_dir):
            for fname in files:
                if not (fname.endswith('.xlsx') and 'entity_metrics' in fname.lower()):
                    continue
                
                llm = extract_llm_from_filename(fname, available_models)
                if not llm:
                    continue
                
                key = (baseline, llm)
                if key not in runs_data:
                    runs_data[key] = {field: {'f1': [], 'prec': [], 'rec': []} for field in det_fields}
                
                try:
                    excel_file = os.path.join(root, fname)
                    df = pd.read_excel(excel_file, sheet_name='Summary')
                    
                    for field in det_fields:
                        field_row = df[df['Field'].str.lower() == field.lower()]
                        if len(field_row) == 0:
                            continue
                        
                        f1_val = float(field_row['F1_Score'].values[0]) if 'F1_Score' in df.columns else 0.0
                        prec_val = float(field_row['Precision'].values[0]) if 'Precision' in df.columns else 0.0
                        rec_val = float(field_row['Recall'].values[0]) if 'Recall' in df.columns else 0.0
                        
                        runs_data[key][field]['f1'].append(f1_val)
                        runs_data[key][field]['prec'].append(prec_val)
                        runs_data[key][field]['rec'].append(rec_val)
                except Exception as e:
                    continue
    
    # Second pass: aggregate runs to compute means and stds
    for (baseline, llm), field_runs in runs_data.items():
        if baseline not in det_data:
            det_data[baseline] = {}
        
        det_data[baseline][llm] = {}
        for field in det_fields:
            if field_runs[field]['f1']:
                det_data[baseline][llm][field] = {
                    'f1': {
                        'm': float(np.mean(field_runs[field]['f1'])),
                        's': float(np.std(field_runs[field]['f1']))
                    },
                    'prec': {
                        'm': float(np.mean(field_runs[field]['prec'])),
                        's': float(np.std(field_runs[field]['prec']))
                    },
                    'rec': {
                        'm': float(np.mean(field_runs[field]['rec'])),
                        's': float(np.std(field_runs[field]['rec']))
                    }
                }
    
    return det_data


def collect_similarity_distribution(available_models: List[str], results_dir: str = "results_runs") -> Dict:
    """
    Collect stacked similarity categories separated by metric (BERT/ROUGE).
    Aggregates across multiple runs: sums counts, then divides by number of runs to get average.
    Excludes 'Non-existent' vulnerabilities (invented by LLM, not in baseline).
    
    Returns: { metric: { baseline: { model: [%HighlySimilar, %ModeratelySimilar, %SlightlySimilar, %Divergent, %Absent] } } }
    """
    stacked_data = {}
    categories = ['Highly Similar', 'Moderately Similar', 'Slightly Similar', 'Divergent', 'Absent']
    metrics = ['bert', 'rouge']
    
    results_path = Path(results_dir)
    if not results_path.exists():
        return stacked_data
    
    # Collect by metric, baseline, and model
    runs_data = {}  # (metric, baseline, model) -> [{cat1: count, cat2: count, ...}, ...]
    
    for baseline_dir in results_path.iterdir():
        if not baseline_dir.is_dir():
            continue
        
        baseline = baseline_dir.name
        
        for root, dirs, files in os.walk(baseline_dir):
            for fname in files:
                if not fname.endswith('.xlsx'):
                    continue
                
                # Check if file matches metric pattern
                metric_match = None
                for m in metrics:
                    if f'{m}_comparison_vulnerabilities' in fname.lower():
                        metric_match = m
                        break
                
                if metric_match is None:
                    continue
                
                llm = extract_llm_from_filename(fname, available_models)
                if not llm:
                    continue
                
                try:
                    excel_file = os.path.join(root, fname)
                    df = pd.read_excel(excel_file, sheet_name='Categorization')
                    
                    if 'Category' in df.columns:
                        # Count each category (including Non-existent for later filtering)
                        cat_counts = {}
                        for cat in categories + ['Non-existent']:
                            cat_counts[cat] = len(df[df['Category'] == cat])
                        
                        key = (metric_match, baseline, llm)
                        if key not in runs_data:
                            runs_data[key] = []
                        runs_data[key].append(cat_counts)
                except Exception as e:
                    continue
    
    # Aggregate runs by metric -> baseline -> model
    for (metric, baseline, llm), run_counts_list in runs_data.items():
        if metric not in stacked_data:
            stacked_data[metric] = {}
        if baseline not in stacked_data[metric]:
            stacked_data[metric][baseline] = {}
        
        # Sum all categories across runs
        avg_counts = {}
        for cat in categories + ['Non-existent']:
            avg_counts[cat] = sum(run[cat] for run in run_counts_list) / len(run_counts_list)
        
        # Filter out Non-existent and calculate percentages
        total = sum(avg_counts.get(cat, 0) for cat in categories)
        if total > 0:
            percentages = [avg_counts.get(cat, 0) / total * 100 for cat in categories]
        else:
            percentages = [0.0] * len(categories)
        
        stacked_data[metric][baseline][llm] = percentages
    
    return stacked_data


def collect_matched_rate_data(available_models: List[str], results_dir: str = "results_runs") -> Dict:
    """
    Collect matched rate: percentage of vulnerabilities extracted that were matched with baseline.
    
    For each run, reads the comparison file (bert/rouge_comparison_vulnerabilities) and calculates:
    (matched_count with _status='OK' / total_extracted_vulnerabilities) * 100
    
    Then aggregates across multiple runs: mean and std of percentages.
    
    Example: If 34 vulnerabilities matched (_status=OK) out of 46 total extracted → 73.91% matched rate
    
    Returns: { baseline: { model: {m: percentage_mean, s: percentage_std} } }
    """
    matched_rate_data = {}
    results_path = Path(results_dir)
    
    if not results_path.exists():
        return matched_rate_data
    
    # Collect data by (baseline, model)
    runs_data = {}  # (baseline, model) -> [list of matched_rate percentages]
    
    for baseline_dir in results_path.iterdir():
        if not baseline_dir.is_dir():
            continue
        
        baseline = baseline_dir.name
        
        for root, dirs, files in os.walk(baseline_dir):
            for fname in files:
                # Look for comparison files (bert or rouge)
                if not fname.endswith('.xlsx') or 'comparison_vulnerabilities' not in fname.lower():
                    continue
                
                llm = extract_llm_from_filename(fname, available_models)
                if not llm:
                    continue
                
                try:
                    excel_file = os.path.join(root, fname)
                    # Read Per_Vulnerability sheet which has row per vulnerability
                    df = pd.read_excel(excel_file, sheet_name='Per_Vulnerability')
                    
                    if '_status' not in df.columns:
                        continue
                    
                    # Count matched vulnerabilities (status == 'OK')
                    matched_count = (df['_status'] == 'OK').sum()
                    total_vulns = len(df)
                    
                    if total_vulns == 0:
                        continue
                    
                    # Calculate percentage for this run
                    percentage = (matched_count / total_vulns) * 100
                    
                    key = (baseline, llm)
                    if key not in runs_data:
                        runs_data[key] = []
                    runs_data[key].append(percentage)
                
                except Exception as e:
                    continue
    
    # Calculate mean and std for each baseline/model combination
    for (baseline, llm), percentages in runs_data.items():
        if baseline not in matched_rate_data:
            matched_rate_data[baseline] = {}
        
        if percentages:
            matched_rate_data[baseline][llm] = {
                'm': float(np.mean(percentages)),
                's': float(np.std(percentages))
            }
    
    return matched_rate_data


def collect_recall_data(available_models: List[str], results_dir: str = "results_runs") -> Dict:
    """
    Collect recall (coverage) data: percentage of vulnerabilities from baseline that were successfully extracted.
    
    Recall = (vulnerabilities found in baseline) / (total vulnerabilities in baseline) * 100
    
    For each run, reads the comparison file (Categorization sheet) and calculates:
    (total_baseline - absent_count) / total_baseline * 100
    
    Then aggregates across multiple runs: mean and std of percentages.
    
    Example: If baseline has 34 vulnerabilities and model identified 32 → 94.1% recall
    
    Returns: { baseline: { model: {m: percentage_mean, s: percentage_std} } }
    """
    recall_data = {}
    results_path = Path(results_dir)
    
    if not results_path.exists():
        return recall_data
    
    # Collect data by (baseline, model)
    runs_data = {}  # (baseline, model) -> [list of recall percentages]
    
    for baseline_dir in results_path.iterdir():
        if not baseline_dir.is_dir():
            continue
        
        baseline = baseline_dir.name
        
        for root, dirs, files in os.walk(baseline_dir):
            for fname in files:
                # Look for comparison files (bert or rouge)
                if not fname.endswith('.xlsx') or 'comparison_vulnerabilities' not in fname.lower():
                    continue
                
                llm = extract_llm_from_filename(fname, available_models)
                if not llm:
                    continue
                
                try:
                    excel_file = os.path.join(root, fname)
                    # Read Categorization sheet which contains all vulnerabilities (baseline + extracted)
                    df = pd.read_excel(excel_file, sheet_name='Categorization')
                    
                    if 'Category' not in df.columns:
                        continue
                    
                    # Count total baseline vulnerabilities and absent ones
                    total_baseline = len(df)
                    absent_count = (df['Category'] == 'Absent').sum()
                    found_count = total_baseline - absent_count
                    
                    if total_baseline == 0:
                        continue
                    
                    # Calculate recall percentage for this run
                    percentage = (found_count / total_baseline) * 100
                    
                    key = (baseline, llm)
                    if key not in runs_data:
                        runs_data[key] = []
                    runs_data[key].append(percentage)
                
                except Exception as e:
                    continue
    
    # Calculate mean and std for each baseline/model combination
    for (baseline, llm), percentages in runs_data.items():
        if baseline not in recall_data:
            recall_data[baseline] = {}
        
        if percentages:
            recall_data[baseline][llm] = {
                'm': float(np.mean(percentages)),
                's': float(np.std(percentages))
            }
    
    return recall_data


def collect_absent_nonexistent_data(available_models: List[str], results_dir: str = "results_runs") -> Dict:
    """
    Collect absent and non-existent vulnerability counts.
    Aggregates ALL data across ALL baselines for each model.
    
    Returns: { model: { 'Absent': std, 'Non-existent': std } }
    """
    absent_nonexistent_data = {}
    results_path = Path(results_dir)
    
    if not results_path.exists():
        return absent_nonexistent_data
    
    # Collect all values (no baseline separation like in original process_results.py)
    runs_data = {}  # model -> { 'Absent': [...], 'Non-existent': [...] }
    
    for baseline_dir in results_path.iterdir():
        if not baseline_dir.is_dir():
            continue
        
        baseline = baseline_dir.name
        
        for root, dirs, files in os.walk(baseline_dir):
            for fname in files:
                if not fname.endswith('.xlsx'):
                    continue
                
                llm = extract_llm_from_filename(fname, available_models)
                if not llm:
                    continue
                
                try:
                    excel_file = os.path.join(root, fname)
                    df = pd.read_excel(excel_file)
                    
                    # Find absent and non-existent columns
                    absent_col = None
                    nonexistent_col = None
                    
                    for c in df.columns:
                        if c.lower() in ['absent', 'absent_count']:
                            absent_col = c
                        if c.lower() in ['invented', 'nonexistent_count', 'non-existent', 'non_existent_count']:
                            nonexistent_col = c
                    
                    if absent_col is None or nonexistent_col is None:
                        continue
                    
                    if llm not in runs_data:
                        runs_data[llm] = {'Absent': [], 'Non-existent': []}
                    
                    # Collect all values from this file (each row is a data point)
                    absent_vals = df[absent_col].dropna().tolist()
                    nonexistent_vals = df[nonexistent_col].dropna().tolist()
                    
                    if absent_vals:
                        runs_data[llm]['Absent'].extend(absent_vals)
                    if nonexistent_vals:
                        runs_data[llm]['Non-existent'].extend(nonexistent_vals)
                
                except Exception as e:
                    continue
    
    # Calculate std for each category (aggregated across all baselines)
    for llm, categories_data in runs_data.items():
        result = {}
        for cat, values in categories_data.items():
            if values:
                result[cat] = float(np.std(values))
            else:
                result[cat] = 0.0
        
        absent_nonexistent_data[llm] = result
    
    return absent_nonexistent_data


def collect_fdr_fnr_data(vulnerability_counts: Dict) -> Dict:
    """
    Derive FDR and FNR per (model, baseline) from already-collected vulnerability_counts.
    FDR = 1 - precision  (Invented / (Invented + Matched))
    FNR = 1 - recall     (Absent   / (Absent + Matched))

    Returns:
      { model: { baseline: {'FDR': float, 'FNR': float},
                 'mean':    {'FDR': float, 'FNR': float} } }
    """
    result = {}
    for baseline, models_dict in vulnerability_counts.items():
        for model, stats in models_dict.items():
            fdr = round(1.0 - stats.get('precision', 0.0), 4)
            fnr = round(1.0 - stats.get('recall', 0.0), 4)
            result.setdefault(model, {})[baseline] = {'FDR': fdr, 'FNR': fnr}

    for model, baselines_dict in result.items():
        pts = [v for k, v in baselines_dict.items() if k != 'mean']
        if pts:
            result[model]['mean'] = {
                'FDR': round(float(np.mean([p['FDR'] for p in pts])), 4),
                'FNR': round(float(np.mean([p['FNR'] for p in pts])), 4),
            }

    return result


def collect_vulnerability_counts(available_models: List[str], results_dir: str = "results_runs") -> Dict:
    """
    Collect absolute vulnerability counts from summary files.
    For each baseline/model pair, gets:
    - total_baseline: Total vulnerabilities in baseline (from summary)
    - extracted_per_model: Count of vulnerabilities extracted by each model
    - matched_per_model: Count of matched vulnerabilities
    
    Returns: { baseline: { model: {baseline_total, extracted_mean, matched_mean, ...} } }
    """
    counts_data = {}
    results_path = Path(results_dir)
    
    if not results_path.exists():
        return counts_data
    
    # Collect baseline totals per baseline from summary files
    baseline_totals = {}  # baseline -> total_count
    
    # Aggregate extracted/matched per baseline/model from summary files
    model_counts = {}  # (baseline, model) -> {baseline_total, extracted: [...], matched: [...]}
    
    for baseline_dir in results_path.iterdir():
        if not baseline_dir.is_dir():
            continue
        
        baseline = baseline_dir.name
        
        for root, dirs, files in os.walk(baseline_dir):
            for fname in files:
                # Look for summary files, priority to BERT then ROUGE
                if not fname.endswith('.xlsx') or 'summary_all_extractions' not in fname.lower():
                    continue
                
                llm = extract_llm_from_filename(fname, available_models)
                if not llm:
                    continue
                
                try:
                    excel_file = os.path.join(root, fname)
                    df = pd.read_excel(excel_file)
                    
                    # Read Baseline_Total_Vulnerabilities from first row
                    if 'Baseline_Total_Vulnerabilities' in df.columns:
                        baseline_total = int(df['Baseline_Total_Vulnerabilities'].iloc[0])
                    else:
                        baseline_total = 0
                    
                    # Read Matched and other metrics from first row
                    matched = int(df['Matched'].iloc[0]) if 'Matched' in df.columns else 0
                    
                    # Store for this model
                    key = (baseline, llm)
                    if key not in model_counts:
                        model_counts[key] = {
                            'baseline_total': baseline_total, 
                            'extracted': [], 
                            'matched': [],
                            'invented': []
                        }
                    
                    # Append total vulnerabilities and matched count
                    total_extracted = int(df['Total_Vulnerabilities'].iloc[0]) if 'Total_Vulnerabilities' in df.columns else 0
                    invented = int(df['Invented'].iloc[0]) if 'Invented' in df.columns else 0
                    model_counts[key]['extracted'].append(total_extracted)
                    model_counts[key]['matched'].append(matched)
                    model_counts[key]['invented'].append(invented)
                    
                    # Update baseline totals (should be same across all models)
                    if baseline not in baseline_totals:
                        baseline_totals[baseline] = baseline_total
                
                except Exception as e:
                    continue
    
    
    # Aggregate and build final structure
    for (baseline, llm), counts in model_counts.items():
        if baseline not in counts_data:
            counts_data[baseline] = {}
        
        if counts['extracted']:
            extracted_mean = float(np.mean(counts['extracted']))
            matched_mean = float(np.mean(counts['matched']))
            baseline_total = counts['baseline_total']
            
            # Calculate precision and recall
            precision = matched_mean / extracted_mean if extracted_mean > 0 else 0
            recall = matched_mean / baseline_total if baseline_total > 0 else 0
            
            # Calculate F1-Score
            f1_score = 0
            if precision + recall > 0:
                f1_score = 2 * (precision * recall) / (precision + recall)
            
            counts_data[baseline][llm] = {
                'baseline_total': baseline_total,
                'extracted_mean': extracted_mean,
                'extracted_std': float(np.std(counts['extracted'])),
                'matched_mean': matched_mean,
                'matched_std': float(np.std(counts['matched'])),
                'precision': float(precision),
                'recall': float(recall),
                'f1_score': float(f1_score)
            }
    
    return counts_data


def collect_error_breakdown(available_models: List[str], results_dir: str = "results_runs", top_n: int = 15) -> Dict:
    """
    Collect error breakdown analysis: which vulnerabilities do models consistently fail to extract?
    
    Identifies "Absent" vulnerabilities (in baseline but not extracted by model) and aggregates
    across all models/runs to find which vulnerabilities are hardest to extract.
    
    Returns: { baseline: [
        {
            'vulnerability': name,
            'failed_models': count_of_models_that_failed,
            'total_models': total_models,
            'failure_rate': failed_models / total_models,
            'avg_bert_score': average_bert_score_when_attempted (or null if always absent)
        },
        ...
    ] } (sorted by failure_rate descending, top N only)
    """
    error_breakdown = {}
    results_path = Path(results_dir)
    
    if not results_path.exists():
        return error_breakdown
    
    # Collect per baseline: vulnerability -> {failed_count: N, total_count: M, bert_scores: []}
    baseline_vuln_data = {}  # baseline -> { vulnerability: {failed: int, total: int, scores: []} }
    
    for baseline_dir in results_path.iterdir():
        if not baseline_dir.is_dir():
            continue
        
        baseline = baseline_dir.name
        baseline_vuln_data[baseline] = {}
        
        for root, dirs, files in os.walk(baseline_dir):
            for fname in files:
                # Look for BERT comparison files (they have the best categorization data)
                if not fname.endswith('.xlsx') or 'bert_comparison_vulnerabilities' not in fname.lower():
                    continue
                
                llm = extract_llm_from_filename(fname, available_models)
                if not llm:
                    continue
                
                try:
                    excel_file = os.path.join(root, fname)
                    # Read Categorization sheet which has Category and BERTScore columns
                    df = pd.read_excel(excel_file, sheet_name='Categorization')
                    
                    if 'Category' not in df.columns or 'Vulnerability_Name' not in df.columns:
                        continue
                    
                    # Look for BERT score column (may be named differently)
                    score_col = None
                    for col in df.columns:
                        if 'bert' in col.lower() and ('score' in col.lower() or 'f1' in col.lower()):
                            score_col = col
                            break
                    
                    # Process each vulnerability
                    for idx, row in df.iterrows():
                        vuln_name = row['Vulnerability_Name']
                        category = row['Category']
                        
                        if pd.isna(vuln_name):
                            continue
                        
                        # Initialize if first time seeing this vulnerability
                        if vuln_name not in baseline_vuln_data[baseline]:
                            baseline_vuln_data[baseline][vuln_name] = {
                                'failed': 0,
                                'total': 0,
                                'scores': []
                            }
                        
                        baseline_vuln_data[baseline][vuln_name]['total'] += 1
                        
                        # Count as failed if "Absent" or "Non-existent"
                        if category in ['Absent', 'Non-existent']:
                            baseline_vuln_data[baseline][vuln_name]['failed'] += 1
                        else:
                            # Record BERT score for "succeeded" cases
                            if score_col and not pd.isna(row[score_col]):
                                baseline_vuln_data[baseline][vuln_name]['scores'].append(float(row[score_col]))
                
                except Exception as e:
                    continue
    
    # Build output: aggregate and compute statistics
    for baseline, vuln_dict in baseline_vuln_data.items():
        results_list = []
        
        for vuln_name, data in vuln_dict.items():
            if data['total'] == 0:
                continue
            
            failure_rate = data['failed'] / data['total']
            avg_score = float(np.mean(data['scores'])) if data['scores'] else None
            
            results_list.append({
                'vulnerability': vuln_name,
                'failed_models': data['failed'],
                'total_models': data['total'],
                'failure_rate': float(failure_rate),
                'avg_bert_score': avg_score
            })
        
        # Sort by failure_rate descending, then by failed_models descending
        results_list.sort(key=lambda x: (-x['failure_rate'], -x['failed_models']))
        
        # Keep only top N
        error_breakdown[baseline] = results_list[:top_n]
    
    return error_breakdown
