"""
Entity Metrics Evaluation - F1/Precision/Recall for Deterministic Fields

Evaluates extraction accuracy for deterministic fields (cvss, severity, port, protocol, plugin)
using standard ML metrics (F1-score, Precision, Recall).

Reads matched pairs from BERT or ROUGE output and calculates metrics for deterministic fields.
Priority: BERT > ROUGE
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[2]))

import pandas as pd
import numpy as np
from pathlib import Path
import warnings
import os
import io
from typing import Dict, List, Tuple, Optional

warnings.filterwarnings("ignore")

# Configure UTF-8 encoding for Windows/Linux compatibility
if sys.platform.startswith('win'):
    if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')
    os.environ['PYTHONIOENCODING'] = 'utf-8'

# Add root directory to path
sys.path.insert(0, str(Path(__file__).parents[1]))

from metrics.common.cli import parse_arguments_common
from metrics.common.field_mapper import (
    get_deterministic_fields,
    normalize_field_value,
    build_field_map,
    get_actual_column_name
)

# ===========================
# CONFIG
# ===========================
BASELINE_SHEET = "Vulnerabilities"


def find_metric_comparison_file(output_dir: Path, model_name: str) -> Tuple[Optional[Path], str]:
    """
    Find BERT or ROUGE comparison file (priority: BERT > ROUGE).
    Returns (file_path, metric_type) or (None, None) if not found.
    """
    # Priority 1: BERT
    bert_file = output_dir / f"bert_comparison_vulnerabilities_{model_name}.xlsx"
    if bert_file.exists():
        return bert_file, "bert"
    
    # Priority 2: ROUGE
    rouge_file = output_dir / f"rouge_comparison_vulnerabilities_{model_name}.xlsx"
    if rouge_file.exists():
        return rouge_file, "rouge"
    
    return None, None


def calculate_field_metrics(baseline_values: List[str], extraction_values: List[str]) -> Dict:
    """
    Calculate precision, recall, F1 for a field across matched pairs.
    
    For each matched pair:
    - True Positive (TP): values match exactly
    - False Positive (FP): extraction value present but doesn't match
    - False Negative (FN): baseline value present but extraction is empty/different
    """
    if not baseline_values:
        return {
            'precision': 0.0,
            'recall': 0.0,
            'f1': 0.0,
            'total_pairs': 0,
            'correct_matches': 0,
            'missing_values': 0,
            'mismatched_values': 0
        }
    
    correct = sum(1 for b, e in zip(baseline_values, extraction_values) if b == e)
    missing = sum(1 for b, e in zip(baseline_values, extraction_values) if e == "" and b != "")
    mismatched = sum(1 for b, e in zip(baseline_values, extraction_values) if b != e and e != "")
    
    total = len(baseline_values)
    
    # Precision: correct / (correct + mismatched)
    precision = correct / (correct + mismatched) if (correct + mismatched) > 0 else 0.0
    
    # Recall: correct / (correct + missing)
    recall = correct / (correct + missing) if (correct + missing) > 0 else 0.0
    
    # F1: harmonic mean
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    
    return {
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'total_pairs': total,
        'correct_matches': correct,
        'missing_values': missing,
        'mismatched_values': mismatched
    }


def main():
    """Main entity metrics evaluation - reads from BERT/ROUGE comparison output."""
    args = parse_arguments_common(require_model=False)
    
    print("\n" + "="*60)
    print("[ENTITY] Entity Metrics Evaluation (F1/Precision/Recall)")
    print("="*60)
    
    baseline_file = args.baseline_file
    extraction_file = args.extraction_file
    output_dir = Path(args.output_dir)
    model_name = getattr(args, 'llm', None) or "model"
    baseline_name = Path(baseline_file).stem.replace(" ", "_").lower()
    
    # Validate baseline name
    if not baseline_name or baseline_name.strip() == "":
        baseline_name = "baseline"
    
    print(f"[ENTITY] Baseline: {baseline_file}")
    print(f"[ENTITY] Extraction: {extraction_file}")
    print(f"[ENTITY] Model: {model_name}")
    print(f"[ENTITY] Baseline Name: {baseline_name}")
    
    # Create output directory before any file operations
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"[ERROR] Failed to create output directory {output_dir}: {e}")
        return
    
    try:
        # Find BERT or ROUGE comparison file (priority: BERT > ROUGE)
        metric_file, metric_type = find_metric_comparison_file(output_dir, model_name)
        
        if not metric_file:
            print(f"[ERROR] No BERT/ROUGE comparison file found in {output_dir}")
            print(f"[ERROR] Expected: bert_comparison_vulnerabilities_{model_name}.xlsx")
            print(f"[ERROR]        or rouge_comparison_vulnerabilities_{model_name}.xlsx")
            return
        
        print(f"[ENTITY] Reading matched pairs from: {metric_file.name} ({metric_type.upper()})")
        
        # Load matched pairs from BERT/ROUGE output
        per_vuln_df = pd.read_excel(metric_file, sheet_name="Per_Vulnerability", engine="openpyxl")
        
        # Filter only matched pairs (BERT uses "_status": "OK", ROUGE uses "_status": "MATCHED")
        matched_df = per_vuln_df[per_vuln_df["_status"].isin(["OK", "MATCHED"])].reset_index(drop=True)
        
        if matched_df.empty:
            print("[ENTITY] No matched pairs found in comparison file.")
            return
        
        print(f"[ENTITY] Matched pairs: {len(matched_df)}")
        
        # Also load mapping debug to get baseline-extraction correlation
        try:
            mapping_df = pd.read_excel(metric_file, sheet_name="Mapping_Debug", engine="openpyxl")
        except Exception as e:
            print(f"[ENTITY] Warning: Could not read Mapping_Debug sheet: {e}")
            mapping_df = None
        
        # Load baseline and extraction data to get field values
        baseline_df = pd.read_excel(baseline_file, sheet_name=BASELINE_SHEET, engine="openpyxl")
        extraction_df = pd.read_excel(extraction_file, sheet_name=BASELINE_SHEET, engine="openpyxl")
        
        # Get deterministic fields from field mapper
        deterministic_fields = sorted(get_deterministic_fields(baseline_df.columns))
        field_map = build_field_map(baseline_df.columns)
        
        if not deterministic_fields:
            print("[ENTITY] No deterministic fields found in baseline.")
            return
        
        print(f"[ENTITY] Found deterministic fields: {deterministic_fields}")
        
        # Create name→index mappings for faster lookup
        baseline_name_idx = {}
        for idx, name in enumerate(baseline_df['Name'].astype(str).str.strip()):
            if name not in baseline_name_idx:  # Keep first occurrence
                baseline_name_idx[name.lower()] = idx
        
        extraction_name_idx = {}
        for idx, name in enumerate(extraction_df['Name'].astype(str).str.strip()):
            if name not in extraction_name_idx:
                extraction_name_idx[name.lower()] = idx
        
        # Calculate metrics for each deterministic field
        field_metrics = {}
        detailed_results = []
        
        for field_lower in deterministic_fields:
            actual_col = field_map[field_lower]
            baseline_vals = []
            extraction_vals = []
            vuln_names = []
            
            # For each matched pair, find the baseline and extraction values
            for _, match_row in matched_df.iterrows():
                extraction_name = str(match_row.get('Name', '')).strip()
                
                # Find extraction index by name
                extraction_idx = extraction_name_idx.get(extraction_name.lower())
                if extraction_idx is None:
                    continue
                
                # For baseline, need to correlate from mapping_df
                matched_baseline_name = None
                if mapping_df is not None:
                    # Find in mapping_df
                    ext_in_mapping = mapping_df[mapping_df['Extraction_Name'].astype(str).str.strip().str.lower() == extraction_name.lower()]
                    if not ext_in_mapping.empty:
                        matched_baseline_name = str(ext_in_mapping.iloc[0]['Baseline_Name_matched']).strip()
                
                # If not found in mapping, try to infer (may not work for duplicates)
                if matched_baseline_name is None:
                    matched_baseline_name = extraction_name
                
                baseline_idx = baseline_name_idx.get(matched_baseline_name.lower())
                if baseline_idx is None:
                    continue
                
                # Extract field values
                try:
                    # Use generic normalization from field_mapper
                    b_val = normalize_field_value(baseline_df.iloc[baseline_idx][actual_col], field_lower)
                    e_val = normalize_field_value(extraction_df.iloc[extraction_idx][actual_col], field_lower)
                    
                    baseline_vals.append(b_val)
                    extraction_vals.append(e_val)
                    vuln_names.append(extraction_name)
                    
                except Exception as e:
                    # Skip if can't extract
                    continue
            
            if not baseline_vals:
                print(f"[ENTITY] Field '{field_lower}': no data could be extracted.")
                continue
            
            # Calculate metrics
            metrics = calculate_field_metrics(baseline_vals, extraction_vals)
            field_metrics[field_lower] = metrics
            
            # Build detailed results for XLSX
            for name, b_val, e_val in zip(vuln_names, baseline_vals, extraction_vals):
                detailed_results.append({
                    'Name': name,
                    'Field': field_lower,
                    'Baseline_Value': b_val,
                    'Extraction_Value': e_val,
                    'Match': 'Yes' if b_val == e_val else 'No',
                    'Status': 'Correct' if b_val == e_val else ('Missing' if e_val == "" else 'Mismatched')
                })
            
            # Print summary
            print(f"\n[ENTITY] {field_lower}:")
            print(f"         Precision: {metrics['precision']:.3f}")
            print(f"         Recall:    {metrics['recall']:.3f}")
            print(f"         F1-Score:  {metrics['f1']:.3f}")
            print(f"         Correct:   {metrics['correct_matches']}/{metrics['total_pairs']}")
            if metrics['missing_values'] > 0:
                print(f"         Missing:   {metrics['missing_values']}")
            if metrics['mismatched_values'] > 0:
                print(f"         Mismatched: {metrics['mismatched_values']}")
        
        # Create summary DataFrame
        summary_data = []
        for field, metrics in field_metrics.items():
            summary_data.append({
                'Field': field,
                'Precision': metrics['precision'],
                'Recall': metrics['recall'],
                'F1_Score': metrics['f1'],
                'Total_Pairs': metrics['total_pairs'],
                'Correct': metrics['correct_matches'],
                'Missing': metrics['missing_values'],
                'Mismatched': metrics['mismatched_values']
            })
        
        if not summary_data:
            print("[ENTITY] No metrics could be calculated.")
            return
        
        summary_df = pd.DataFrame(summary_data)
        
        # Create detailed results DataFrame
        detailed_df = pd.DataFrame(detailed_results) if detailed_results else pd.DataFrame()
        
        # Save to XLSX with proper path handling
        output_file = f"entity_metrics_{baseline_name}_{model_name}.xlsx"
        output_path = output_dir / output_file
        
        # Debug logging
        print(f"\n[ENTITY] Saving to: {output_path}")
        print(f"[ENTITY] Output dir exists: {output_dir.exists()}")
        print(f"[ENTITY] Output dir is dir: {output_dir.is_dir()}")
        
        # Ensure output path is properly formatted as string
        output_path_str = str(output_path)
        if not output_path_str.endswith('.xlsx'):
            output_path_str += '.xlsx'
        
        with pd.ExcelWriter(output_path_str) as writer:
            summary_df.to_excel(writer, sheet_name="Summary", index=False)
            if not detailed_df.empty:
                detailed_df.to_excel(writer, sheet_name="Detailed", index=False)
        
        print(f"[ENTITY] Results saved: {output_path_str}")
        print(f"{'='*60}")
        
    except Exception as e:
        print(f"[ERROR] Entity metrics failed: {e}")
        print(f"[DEBUG] baseline_file: {args.baseline_file}")
        print(f"[DEBUG] extraction_file: {args.extraction_file}")
        print(f"[DEBUG] output_dir: {args.output_dir}")
        print(f"[DEBUG] baseline_name: {baseline_name if 'baseline_name' in locals() else 'NOT_SET'}")
        print(f"[DEBUG] model_name: {model_name if 'model_name' in locals() else 'NOT_SET'}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
