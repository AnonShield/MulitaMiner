import argparse
import subprocess
import os
import sys
import time
import json
import shutil
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.utils.reporting import generate_final_report


def str_to_bool(val):
    return val.lower() in ['true', '1', 'yes', 'sim']


def get_base(filename):
    return os.path.splitext(os.path.basename(filename))[0]


def make_checkpoint_path(ts):
    return f"run_checkpoints_{ts}.json"


def main():
    """Execute extraction and evaluation experiments in batch mode."""
    parser = argparse.ArgumentParser(description="Run extraction and evaluation experiments.")
    parser.add_argument('--input-dir', type=str, required=True, help='Directory containing .xlsx (baseline) and .pdf (report) files. Both must have the same name, except for the extension.')
    parser.add_argument('--llms', type=str, nargs='+', required=True, help='List of LLMs to test.')
    parser.add_argument('--scanners', type=str, nargs='+', required=True, help='List of scanners to test.')
    parser.add_argument('--evaluation-methods', type=str, nargs='+', default=['bert'], help='List of evaluation methods (e.g., bert, rouge).')
    parser.add_argument('--runs-per-model', type=int, default=10, help='Number of runs per model.')
    parser.add_argument('--allow-duplicates', type=str, nargs='+', default=[], help='List of true/false values corresponding to the order of scanners. Example: --scanners openvas tenable --allow-duplicates true false (openvas=True, tenable=False).')
    parser.add_argument('--checkpoint-file', type=str, default=None, help='Checkpoint file to use.')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging of raw LLM responses.')
    parser.add_argument('--debug-dir', type=str, default='llm_debug_responses', help='Directory for debug logs.')
    args, unknown = parser.parse_known_args()

    if unknown:
        print(f"\nError: Unrecognized arguments: {unknown}")
        print("Check for typos in the arguments.")
        sys.exit(1)

    if len(args.allow_duplicates) != len(args.scanners):
        print(f"[ERROR] The number of values in --allow-duplicates must match the number of scanners.")
        sys.exit(1)
    allow_duplicates_map = {scanner: str_to_bool(allow) for scanner, allow in zip(args.scanners, args.allow_duplicates)}

    print("[INFO] Starting run_experiments.py...")

    input_dir = args.input_dir
    xlsx_files = sorted([f for f in os.listdir(input_dir) if f.endswith('.xlsx')])
    pdf_files = sorted([f for f in os.listdir(input_dir) if f.endswith('.pdf')])
    xlsx_map = {get_base(f): os.path.join(input_dir, f) for f in xlsx_files}
    pdf_map = {get_base(f): os.path.join(input_dir, f) for f in pdf_files}

    matched_pairs = []
    for base in xlsx_map:
        if base in pdf_map:
            matched_pairs.append((xlsx_map[base], pdf_map[base]))
            print(f"[PAIR] Found pair: {base}.xlsx <-> {base}.pdf")
        else:
            print(f"[IGNORED] Baseline '{xlsx_map[base]}' ignored: no matching PDF found.")
    for base in pdf_map:
        if base not in xlsx_map:
            print(f"[IGNORED] Report '{pdf_map[base]}' ignored: no matching .xlsx baseline found.")

    if not matched_pairs:
        print("No matching .xlsx/.pdf pairs found in the provided directory.")
        sys.exit(1)

    print(f"[INFO] Total pairs found: {len(matched_pairs)}")

    baselines = [pair[0] for pair in matched_pairs]
    extractors = [pair[1] for pair in matched_pairs]
    llms = args.llms
    scanners = args.scanners
    evaluation_methods = list(args.evaluation_methods)
    # Note: Entity metrics are automatically added by main.py when --evaluation-methods is used
    runs_per_model = args.runs_per_model

    os.makedirs("results_runs", exist_ok=True)

    print("[INFO] Starting experiment runs...")

    start_time = time.time()
    run_stats = {
        'baseline_counts': {},
        'total_runs': 0,
        'timing_report': []
    }

    checkpoint_id = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    checkpoint_path = make_checkpoint_path(checkpoint_id)
    print(f"[INFO] Checkpoint file: {checkpoint_path}")

    all_run_ids = []
    for baseline_path, extractor_path in zip(baselines, extractors):
        for scanner in scanners:
            for llm in llms:
                for run_num in range(1, runs_per_model + 1):
                    baseline_folder = os.path.splitext(os.path.basename(baseline_path))[0]
                    run_id = f"{baseline_folder}_{llm}_run{run_num}"
                    all_run_ids.append((run_id, baseline_path, extractor_path, scanner, llm, run_num))

    if args.checkpoint_file:
        checkpoint_path = args.checkpoint_file
        with open(checkpoint_path, "r", encoding="utf-8") as f:
            checkpoint_data = json.load(f)
        checkpoints = checkpoint_data["runs"]
        checkpoint_id = checkpoint_data.get("checkpoint_id", datetime.now().strftime("%Y-%m-%dT%H-%M-%S"))
        print(f"[INFO] Resuming from checkpoint: {checkpoint_path}")
    else:
        checkpoint_id = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
        checkpoint_path = f"run_checkpoints_{checkpoint_id}.json"
        checkpoints = {}
        for run_id, baseline_path, extractor_path, scanner, llm, run_num in all_run_ids:
            checkpoints[run_id] = {
                "status": "pending",
                "erro": None,
                "baseline": baseline_path,
                "extractor": extractor_path,
                "scanner": scanner,
                "llm": llm,
                "run_num": run_num,
                "cmd": None,
                "output_file": None,
                "timestamp": None
            }
        checkpoint_data = {"runs": checkpoints, "checkpoint_id": checkpoint_id}
        with open(checkpoint_path, "w", encoding="utf-8") as f:
            json.dump(checkpoint_data, f, indent=2, ensure_ascii=False)
        print(f"[INFO] Created initial checkpoint with {len(all_run_ids)} pending runs: {checkpoint_path}")

    for run_id, run_info in checkpoints.items():
        if run_info.get("status") == "ok":
            print(f"[SKIP] Run already completed: {run_id}")
            continue

        cmd = None
        try:
            baseline_path = run_info['baseline']
            extractor_path = run_info['extractor']
            scanner = run_info['scanner']
            llm = run_info['llm']
            run_num = run_info['run_num']
            
            subdir = os.path.join("results_runs", os.path.splitext(os.path.basename(baseline_path))[0], llm, f"run{run_num}")
            os.makedirs(subdir, exist_ok=True)

            run_prefix = f"{os.path.splitext(os.path.basename(baseline_path))[0]}_{llm}_run{run_num}"
            output_path = os.path.join(subdir, f"{run_prefix}.json")
            output_file = os.path.join(subdir, f"{run_prefix}.txt")
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            allow_duplicates = allow_duplicates_map.get(scanner, False)

            # --- Extraction + Evaluation in main.py ---
            cmd = [
                sys.executable, 'main.py',
                '--input', extractor_path,
                '--scanner', scanner,
                '--llm', llm,
                '--output-file', run_prefix,
                '--output-dir', subdir,
                '--convert', 'all',
                '--baseline-path', baseline_path,
            ]
            
            # Add evaluation methods (entity is automatically added by main.py)
            if evaluation_methods:
                cmd += ['--evaluation-methods'] + evaluation_methods
            
            if allow_duplicates:
                cmd.append('--allow-duplicates')
            
            if args.debug:
                cmd.append('--debug')
            
            if args.debug_dir != 'llm_debug_responses':
                cmd += ['--debug-dir', args.debug_dir]
            
            print(f"Running extraction + evaluation: {' '.join(cmd)}")
            with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace") as proc:
                with open(output_file, "w", encoding="utf-8") as f:
                    for line in proc.stdout:
                        print(line, end="")
                        f.write(line)
                proc.wait()
            
            if proc.returncode != 0:
                raise subprocess.CalledProcessError(proc.returncode, cmd)
            
            checkpoints[run_id]["status"] = "ok"
            checkpoints[run_id]["output_file"] = output_file
            checkpoints[run_id]["timestamp"] = timestamp
            checkpoints[run_id]["cmd"] = " ".join(cmd) if cmd else None
            
            with open(checkpoint_path, "w", encoding="utf-8") as f:
                json.dump(checkpoint_data, f, indent=2, ensure_ascii=False)
            print(f"[CHECKPOINT] Saved to {checkpoint_path} after run {run_id}")

        except Exception as e:
            print(f"[CHECKPOINT] Error in run {run_id}: {e}")
            checkpoints[run_id]["status"] = "error"
            checkpoints[run_id]["erro"] = str(e)
            checkpoints[run_id]["cmd"] = " ".join(cmd) if cmd else None
            with open(checkpoint_path, "w", encoding="utf-8") as f:
                json.dump(checkpoint_data, f, indent=2, ensure_ascii=False)
            print(f"[CHECKPOINT] Saved to {checkpoint_path} after run {run_id}")
            continue

    end_time = time.time()
    duration = end_time - start_time

    print("[INFO] Execution finished. Generating final report...")
    report_dir = os.path.abspath('results_runs')
    generate_final_report(
        start_time=start_time,
        end_time=end_time,
        run_stats=run_stats,
        tokens_dir='results_tokens',
        report_dir=report_dir,
        include_metrics_time=True,
        timing_report=run_stats.get('timing_report', [])
    )
    print("[INFO] Final report generated.")

    print("[INFO] Generating charts with process_results.py...")
    try:
        subprocess.run([
            sys.executable,
            os.path.join(os.path.dirname(__file__), "process_results.py")
        ], check=True)
        print("[INFO] Charts generated successfully.")
    except Exception as e:
        print(f"[ERROR] Failed to generate charts: {e}")

    # ─────────────────────────────────────────────────────────────
    # NEW: Generate interactive metrics report with PNG export
    # ─────────────────────────────────────────────────────────────
    print("\n[INFO] Generating interactive metrics dashboard and PNG charts...")
    try:
        subprocess.run([
            sys.executable,
            os.path.join(os.path.dirname(__file__), "../metrics/plot/metrics.py")
        ], check=True)
        
        # Find and display the generated report
        plot_dir = os.path.abspath('plot_runs')
        if os.path.exists(plot_dir):
            reports = sorted([f for f in os.listdir(plot_dir) 
                            if f.startswith('metrics_report_') and f.endswith('.html')])
            if reports:
                latest_report = os.path.join(plot_dir, reports[-1])
                print(f"\n[SUCCESS] ✨ Interactive report generated!")
                print(f"[SUCCESS] 📊 Open in browser: {latest_report}")
                print(f"[SUCCESS] ⏱️  Total experiment time: {int(duration // 60)}m {int(duration % 60)}s")
        
    except Exception as e:
        print(f"[WARNING] Failed to generate Plotly report: {e}")
        print("[WARNING] Continuing... (legacy charts still generated)")


if __name__ == "__main__":
    main()