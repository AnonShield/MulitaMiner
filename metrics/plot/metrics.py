#!/usr/bin/env python
"""
Main metrics dashboard and report generator.
Generates PNG charts and unified HTML report from experimental results.

Usage:
  python metrics/plot/metrics.py
  python metrics/plot/metrics.py --png-only
  python metrics/plot/metrics.py --report-only --output-dir output/
"""

import os
import sys
import json
import argparse
import numpy as np
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# Add parent directories to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from metrics.plot.plot_generator import MetricsPlotter, SIMILARITY_COLORS
from metrics.plot.report_generator import ReportGenerator
from metrics.plot.data_collector import (
    discover_available_models,
    collect_bert_rouge_data,
    collect_deterministic_data,
    collect_similarity_distribution,
    collect_matched_rate_data,
    collect_recall_data,
    collect_absent_nonexistent_data,
    collect_vulnerability_counts,
    collect_error_breakdown,
    collect_fdr_fnr_data,
)
from metrics.plot.png_generator import (
    generate_similarity_pngs,
    generate_matched_rate_png,
    generate_absent_nonexistent_png,
)


# ============= CONFIGURATION =============
RESULTS_DIR = "results_runs"


# ============= MAIN ORCHESTRATOR =============
def main():
    """Main execution."""
    parser = argparse.ArgumentParser(description="Generate metrics charts and reports.")
    parser.add_argument('--png-only', action='store_true', help='Generate PNGs only (no HTML report)')
    parser.add_argument('--report-only', action='store_true', help='Generate HTML report only (no PNGs)')
    parser.add_argument('--output-dir', default='plot_runs', help='Output directory')
    
    args = parser.parse_args()
    
    if args.png_only and args.report_only:
        print("[ERROR] Cannot use both --png-only and --report-only")
        return 1
    
    print("\n" + "="*70)
    print("[METRICS] MulitaMiner Metrics Dashboard (Chart.js) — Report Generator")
    print("="*70)
    
    start_time = datetime.now()
    
    # Discover baselines
    if not os.path.exists(RESULTS_DIR):
        print(f"\n[ERROR] Results directory not found: {RESULTS_DIR}")
        return 1
    
    baselines = sorted([d for d in os.listdir(RESULTS_DIR) if os.path.isdir(os.path.join(RESULTS_DIR, d))])
    
    if not baselines:
        print(f"\n[ERROR] No baselines found in {RESULTS_DIR}")
        return 1
    
    print(f"\nFound baselines: {baselines}")
    
    # Discover available models dynamically
    available_models = discover_available_models(RESULTS_DIR)
    print(f"Found models: {available_models}")
    
    if not available_models:
        print(f"\n[ERROR] No models found in {RESULTS_DIR}")
        return 1
    
    # Collect Chart.js structured data
    print("\n[INFO] Collecting metrics data for Chart.js...")
    bert_data, rouge_data = collect_bert_rouge_data(available_models)
    det_data = collect_deterministic_data(available_models)
    stacked_data = collect_similarity_distribution(available_models)
    matched_rate_data = collect_matched_rate_data(available_models)
    recall_data = collect_recall_data(available_models)
    absent_nonexistent_data = collect_absent_nonexistent_data(available_models)
    vulnerability_counts = collect_vulnerability_counts(available_models)
    error_breakdown = collect_error_breakdown(available_models)
    fdr_fnr_data = collect_fdr_fnr_data(vulnerability_counts)

    # Detect available data types
    has_bert = any(baseline_data for baseline_data in bert_data.values())
    has_rouge = any(baseline_data for baseline_data in rouge_data.values())
    has_det = any(baseline_data for baseline_data in det_data.values())
    has_stacked = any(any(baseline_data for baseline_data in metric_data.values()) for metric_data in stacked_data.values())
    has_matched = any(baseline_data for baseline_data in matched_rate_data.values())
    has_recall = any(baseline_data for baseline_data in recall_data.values())
    has_absent_nonexist = any(baseline_data for baseline_data in absent_nonexistent_data.values())
    has_vulncount = any(baseline_data for baseline_data in vulnerability_counts.values())
    has_error_breakdown = any(baseline_data for baseline_data in error_breakdown.values())
    has_fdr_fnr = bool(fdr_fnr_data)

    print(f"  • BERT data: {'Yes' if has_bert else 'No'}")
    print(f"  • ROUGE data: {'Yes' if has_rouge else 'No'}")
    print(f"  • Deterministic data: {'Yes' if has_det else 'No'}")
    print(f"  • Similarity distribution: {'Yes' if has_stacked else 'No'}")
    print(f"  • Matched rate data: {'Yes' if has_matched else 'No'}")
    print(f"  • Recall data: {'Yes' if has_recall else 'No'}")
    print(f"  • Absent/Non-existent data: {'Yes' if has_absent_nonexist else 'No'}")
    print(f"  • Vulnerability counts: {'Yes' if has_vulncount else 'No'}")
    print(f"  • Error breakdown: {'Yes' if has_error_breakdown else 'No'}")
    print(f"  • FDR/FNR data: {'Yes' if has_fdr_fnr else 'No'}")

    # Prepare template context
    context = {
        'report_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'baselines': baselines,
        'models': available_models,  # Use dynamically discovered models
        'bert': bert_data,
        'rouge': rouge_data,
        'det': det_data,
        'stacked': stacked_data,
        'matched_rate': matched_rate_data,
        'recall': recall_data,
        'absent_nonexist': absent_nonexistent_data,
        'vulnerability_counts': vulnerability_counts,
        'error_breakdown': error_breakdown,
        'fdr_fnr': fdr_fnr_data,
        'results_dir': os.path.abspath(RESULTS_DIR),
        # Data availability flags
        'has_bert': has_bert,
        'has_rouge': has_rouge,
        'has_det': has_det,
        'has_stacked': has_stacked,
        'has_matched': has_matched,
        'has_recall': has_recall,
        'has_absent_nonexist': has_absent_nonexist,
        'has_vulncount': has_vulncount,
        'has_error_breakdown': has_error_breakdown,
        'has_fdr_fnr': has_fdr_fnr,
    }
    
    # Generate HTML report
    if not args.png_only:
        print("\n[INFO] Generating interactive HTML dashboard (Chart.js)...")
        report_gen = ReportGenerator()
        
        os.makedirs(args.output_dir, exist_ok=True)
        report_path = os.path.join(args.output_dir, f'metrics_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html')
        
        report_gen.generate_metrics_report(
            output_file=report_path,
            **context
        )
        
        print(f"[OK] Report generated: {report_path}")
    
    # Generate PNG charts
    if not args.report_only:
        if has_stacked or has_matched or has_absent_nonexist:
            print("\n[INFO] Generating PNG charts...")
            os.makedirs(args.output_dir, exist_ok=True)
            if has_stacked:
                generate_similarity_pngs(stacked_data, args.output_dir)
            if has_matched or has_recall:
                generate_matched_rate_png(matched_rate_data, recall_data, args.output_dir)
            if has_absent_nonexist:
                generate_absent_nonexistent_png(absent_nonexistent_data, args.output_dir)

    
    # Summary
    end_time = datetime.now()
    duration = end_time - start_time
    execution_time = f"{duration.seconds // 60}m {duration.seconds % 60}s"
    
    print("\n" + "="*70)
    print("[SUCCESS] Metrics generation complete!")
    print(f"[OUTPUT] Directory: {os.path.abspath(args.output_dir)}")
    print(f"[TIME] Execution time: {execution_time}")
    print("="*70 + "\n")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
