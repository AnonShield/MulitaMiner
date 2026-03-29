import argparse
import subprocess
import os
import sys
import os

# Garante que o diretório raiz esteja no sys.path para importar src.utils.reporting
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import time
import json
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from src.utils.reporting import generate_final_report

def str_to_bool(val):
    return val.lower() in ['true', '1', 'yes', 'sim']

def get_base(filename):
    return os.path.splitext(os.path.basename(filename))[0]

def make_checkpoint_path(ts):
    return f"run_checkpoints_{ts}.json"

def main():
    parser = argparse.ArgumentParser(description="Run extraction and evaluation experiments.")
    parser.add_argument('--input-dir', type=str, required=True, help='Directory containing .xlsx (baseline) and .pdf (report) files. Both must have the same name, except for the extension.')
    parser.add_argument('--llms', type=str, nargs='+', required=True, help='List of LLMs to test.')
    parser.add_argument('--scanners', type=str, nargs='+', required=True, help='List of scanners to test.')
    parser.add_argument('--evaluation-methods', type=str, nargs='+', default=['bert'], help='List of evaluation methods (e.g., bert, rouge).')
    parser.add_argument('--runs-per-model', type=int, default=10, help='Number of runs per model.')
    parser.add_argument('--allow-duplicates', type=str, nargs='+', default=[], help='List of true/false values corresponding to the order of scanners. Example: --scanners openvas tenable --allow-duplicates true false (openvas=True, tenable=False).')
    parser.add_argument('--checkpoint-file', type=str, default=None, help='Checkpoint file to use.')
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
    evaluation_methods = args.evaluation_methods
    runs_per_model = args.runs_per_model

    os.makedirs("results_runs", exist_ok=True)

    print("[INFO] Starting experiment runs...")

    # Inicia a contagem de tempo antes de tudo
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
        # Initialize checkpoint with all runs as "pending"
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
        # Create initial checkpoint file immediately
        checkpoint_data = {"runs": checkpoints, "checkpoint_id": checkpoint_id}
        with open(checkpoint_path, "w", encoding="utf-8") as f:
            json.dump(checkpoint_data, f, indent=2, ensure_ascii=False)
        print(f"[INFO] Created initial checkpoint with {len(all_run_ids)} pending runs: {checkpoint_path}")

    # Execute runs - OUTSIDE the if/else block so it works for both new and resumed checkpoints
    for run_id, baseline_path, extractor_path, scanner, llm, run_num in all_run_ids:
        cmd = None  # Initialize cmd to avoid undefined variable errors
        try:
            # Skip if already completed
            if checkpoints.get(run_id, {}).get("status") == "ok":
                print(f"[SKIP] Run already completed: {run_id}")
                continue
            
            subdir = os.path.join("results_runs", os.path.splitext(os.path.basename(baseline_path))[0], llm, f"run{run_num}")
            os.makedirs(subdir, exist_ok=True)

            run_prefix = f"{os.path.splitext(os.path.basename(baseline_path))[0]}_{llm}_run{run_num}_"
            output_file = os.path.join(subdir, f"{run_prefix}.txt")
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            allow_duplicates = allow_duplicates_map.get(scanner, False)

            cmd = [
                sys.executable, "main.py",
                "--input", extractor_path,
                "--scanner", scanner,
                "--llm", llm,
                "--convert", "xlsx",
                "--evaluate",
                "--baseline", baseline_path,
                "--output-dir", subdir,
                "--run-experiments"
                    ]
            if allow_duplicates:
                cmd.append("--allow-duplicates")
            extraction_start = time.time()
            print(f"Running extraction: {' '.join(cmd)}")
            with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace") as proc:
                with open(output_file, "w", encoding="utf-8") as f:
                    for line in proc.stdout:
                        print(line, end="")
                        f.write(line)
                proc.wait()
            extraction_end = time.time()
            extraction_duration = extraction_end - extraction_start

            metric_duration = 0
            pdf_base = os.path.splitext(os.path.basename(extractor_path))[0]
            llm_name = llm.replace('/', '_').replace(':', '_')

            # Metrics
            xlsx_candidates = [f for f in os.listdir(subdir) if f.endswith(".xlsx")]
            if not xlsx_candidates:
                print(f"[ERROR DEBUG] No .xlsx file found in {subdir}")
                raise Exception(f"[ERROR] Extraction .xlsx file not found for {pdf_base} {llm_name}")
            if len(xlsx_candidates) > 1:
                print(f"[WARN] Mais de um arquivo .xlsx encontrado em {subdir}, usando o primeiro: {xlsx_candidates[0]}")
            extraction_xlsx = os.path.join(subdir, xlsx_candidates[0])

            for method in evaluation_methods:
                metric_method_start = time.time()
                if method == "bert":
                    bert_output_dir = subdir  # Salva na pasta da run
                    os.makedirs(bert_output_dir, exist_ok=True)
                    bert_cmd = [
                        sys.executable, "metrics/bert/compare_extractions_bert.py",
                        "--baseline-file", baseline_path,
                        "--extraction-file", extraction_xlsx,
                        "--model", llm,
                        "--output-dir", bert_output_dir
                    ]
                    if allow_duplicates:
                        bert_cmd.append("--allow-duplicates")
                    print(f"Running BERT analysis: {' '.join(bert_cmd)}")
                    result_bert = subprocess.run(bert_cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
                    bert_log = output_file.replace('.txt', '_bert.txt')
                    if result_bert.stdout and result_bert.stdout.strip():
                        with open(bert_log, "w", encoding="utf-8") as f:
                            f.write(result_bert.stdout)
                    if result_bert.stderr and result_bert.stderr.strip():
                        print(f"[STDERR-BERT] {result_bert.stderr}")
                elif method == "rouge":
                    rouge_output_dir = subdir  # Salva na pasta da run
                    os.makedirs(rouge_output_dir, exist_ok=True)
                    rouge_cmd = [
                        sys.executable, "metrics/rouge/compare_extractions_rouge.py",
                        "--baseline-file", baseline_path,
                        "--extraction-file", extraction_xlsx,
                        "--model", llm,
                        "--output-dir", rouge_output_dir
                    ]
                    if allow_duplicates:
                        rouge_cmd.append("--allow-duplicates")
                    print(f"Running ROUGE analysis: {' '.join(rouge_cmd)}")
                    result_rouge = subprocess.run(rouge_cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
                    rouge_log = output_file.replace('.txt', '_rouge.txt')
                    if result_rouge.stdout and result_rouge.stdout.strip():
                        with open(rouge_log, "w", encoding="utf-8") as f:
                            f.write(result_rouge.stdout)
                    if result_rouge.stderr and result_rouge.stderr.strip():
                        print(f"[STDERR-ROUGE] {result_rouge.stderr}")
                metric_method_end = time.time()
                metric_duration += (metric_method_end - metric_method_start)

            total_duration = extraction_duration + metric_duration
            run_stats['timing_report'].append({
                'run_id': run_id,
                'baseline': baseline_path,
                'extractor': extractor_path,
                'scanner': scanner,
                'llm': llm,
                'run_num': run_num,
                'extraction_time': extraction_duration,
                'metric_time': metric_duration,
                'total_time': total_duration
            })

            # Update checkpoints
            checkpoints[run_id] = {
                "status": "ok",
                "erro": None,
                "baseline": baseline_path,
                "extractor": extractor_path,
                "scanner": scanner,
                "llm": llm,
                "run_num": run_num,
                "cmd": cmd,
                "output_file": output_file,
                "timestamp": timestamp
            }
        except Exception as e:
            print(f"[CHECKPOINT] Error in run {run_id}: {e}")
            import traceback
            traceback.print_exc()
            checkpoints[run_id] = {
                "status": "erro",
                "erro": str(e),
                "baseline": baseline_path,
                "extractor": extractor_path,
                "scanner": scanner,
                "llm": llm,
                "run_num": run_num,
                "cmd": cmd or "Command not initialized",
                "output_file": output_file if 'output_file' in locals() else "Not created",
                "timestamp": timestamp if 'timestamp' in locals() else datetime.now().strftime('%Y%m%d_%H%M%S')
            }
        # Save checkpoints after each run
        checkpoint_data = {"runs": checkpoints, "checkpoint_id": checkpoint_id}
        with open(checkpoint_path, "w", encoding="utf-8") as f:
            json.dump(checkpoint_data, f, indent=2, ensure_ascii=False)
        print(f"[CHECKPOINT] Saved to {checkpoint_path} after run {run_id}")
        baseline_key = os.path.basename(baseline_path)
        run_stats['baseline_counts'][baseline_key] = run_stats['baseline_counts'].get(baseline_key, 0) + 1
        run_stats['total_runs'] += 1

    end_time = time.time()
    run_stats['end_time'] = end_time
    run_stats['duration'] = end_time - start_time

    # Gera relatório final ao final de todo o script
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

    # Chama process_results.py para gerar os charts automaticamente
    print("[INFO] Generating charts with process_results.py...")
    try:
        subprocess.run([
            sys.executable,
            os.path.join(os.path.dirname(__file__), "process_results.py")
        ], check=True)
        print("[INFO] Charts generated successfully.")
    except Exception as e:
        print(f"[ERROR] Failed to generate charts: {e}")

if __name__ == "__main__":
    main()



