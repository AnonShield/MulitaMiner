"""Batch experiment runner (CLI).

Discovers .xlsx/.pdf pairs (or resumes a checkpoint), runs extraction per
(baseline × llm × run) via the runner, then does a single post-extraction
metrics pass + report. Heavy lifting lives in mulitaminer.experiments.
"""
import argparse
import json
import os
import subprocess
import sys
import time
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from mulitaminer.reporting.reporting import generate_final_report
from mulitaminer.llm.config_loader import get_provider_key
from mulitaminer.configs.constants import RUNS_DIR, DEBUG_DIR, TOKENS_DIR, PLOTS_DIR
from mulitaminer.experiments.runner import get_base, run_group_sequential
from mulitaminer.experiments.checkpoint import make_checkpoint_path, save_checkpoint


def main():
    """Execute extraction and evaluation experiments in batch mode."""
    parser = argparse.ArgumentParser(description="Run extraction and evaluation experiments.")
    parser.add_argument('--input-dir', type=str, default=None,
                        help='Directory containing .xlsx (baseline) and .pdf (report) files. Both must have the same name, except for the extension.')
    parser.add_argument('--llm', '--llms', dest='llms', type=str, nargs='+', default=None,
                        help='List of LLMs to test (accepts multiple values).')
    parser.add_argument('--scanner', type=str, default=None,
                        help='Scanner to use (e.g., openvas, tenable).')
    parser.add_argument('--metrics', dest='evaluation_methods',
                        type=str, nargs='+', default=None,
                        help=('Metrics to run. Available: bert, rouge, field_f1, schema, severity, '
                              'coverage. Use "all" for every method (recommended). Producer/consumer '
                              'dependencies are auto-resolved (e.g. requesting only "coverage" '
                              'auto-adds "bert").'))
    parser.add_argument('--runs-per-model', type=int, default=None,
                        help='Number of runs per model.')
    parser.add_argument('--allow-duplicates', action='store_true',
                        help='Allow duplicates in results.')
    parser.add_argument('--checkpoint-file', type=str, default=None,
                        help='Checkpoint file to resume from. When provided, all other arguments become optional.')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging of raw LLM responses.')
    parser.add_argument('--debug-dir', type=str, default=str(DEBUG_DIR),
                        help='Directory for debug logs.')
    parser.add_argument('--output-dir', dest='output_dir', type=str, default=str(RUNS_DIR),
                        help='Results root directory where per-run subdirs are created '
                             f'(default: {RUNS_DIR}).')
    parser.add_argument('--metrics-workers', type=int, default=4,
                        help='Parallel workers for the post-experiment metrics pass (default: 4).')
    parser.add_argument('--skip-metrics', action='store_true',
                        help='Skip the post-experiment metrics + aggregator pass.')
    args, unknown = parser.parse_known_args()

    if unknown:
        print(f"\nError: Unrecognized arguments: {unknown}")
        print("Check for typos in the arguments.")
        sys.exit(1)

    if not args.checkpoint_file and not args.input_dir:
        parser.error("--input-dir is required when not using --checkpoint-file")

    print("[INFO] Starting run_experiments.py...")

    start_time = time.time()
    run_stats = {
        'baseline_counts': {},
        'total_runs': 0,
        'timing_report': []
    }

    if args.checkpoint_file:
        # Resume from checkpoint — all run info is self-contained
        checkpoint_path = args.checkpoint_file
        with open(checkpoint_path, "r", encoding="utf-8") as f:
            checkpoint_data = json.load(f)
        checkpoints = checkpoint_data["runs"]
        checkpoint_id = checkpoint_data.get("checkpoint_id", datetime.now().strftime("%Y-%m-%dT%H-%M-%S"))
        meta = checkpoint_data.get("meta", {})
        evaluation_methods = args.evaluation_methods or meta.get("evaluation_methods", ["bert"])
        allow_duplicates = meta.get("allow_duplicates", False)
        # Preserve the original run's debug flags unless explicitly overridden now.
        debug = args.debug or meta.get("debug", False)
        debug_dir = meta.get("debug_dir") or args.debug_dir
        pending = sum(1 for r in checkpoints.values() if r.get("status") != "ok")
        print(f"[INFO] Resuming from checkpoint: {checkpoint_path}")
        print(f"[INFO] Pending runs: {pending} / {len(checkpoints)}")

    else:
        # Fresh run — build everything from args
        if not args.llms:
            parser.error("--llms is required when not using --checkpoint-file")
        if not args.scanner:
            parser.error("--scanner is required when not using --checkpoint-file")

        runs_per_model = args.runs_per_model or 10
        allow_duplicates = args.allow_duplicates
        evaluation_methods = args.evaluation_methods or ["bert"]
        debug = args.debug
        debug_dir = args.debug_dir
        scanner = args.scanner

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

        os.makedirs(args.output_dir, exist_ok=True)

        all_run_ids = []
        for baseline_path, extractor_path in matched_pairs:
            for llm in args.llms:
                for run_num in range(1, runs_per_model + 1):
                    run_id = f"{get_base(baseline_path)}_{llm}_run{run_num}"
                    all_run_ids.append((run_id, baseline_path, extractor_path, scanner, llm, run_num))

        checkpoint_id = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
        checkpoint_path = make_checkpoint_path(checkpoint_id)
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
        checkpoint_data = {
            "runs": checkpoints,
            "checkpoint_id": checkpoint_id,
            "meta": {
                "evaluation_methods": evaluation_methods,
                "allow_duplicates": allow_duplicates,
                "debug": debug,
                "debug_dir": debug_dir,
                "input_dir": input_dir,
            }
        }
        save_checkpoint(checkpoint_path, checkpoint_data)
        print(f"[INFO] Created checkpoint with {len(all_run_ids)} pending runs: {checkpoint_path}")

    print("[INFO] Starting experiment runs...")

    # Group runs by provider for parallelism
    provider_groups = {}
    for run_id, run_info in checkpoints.items():
        key = get_provider_key(run_info['llm'])
        provider_groups.setdefault(key, []).append(run_id)

    parallel = len(provider_groups) > 1
    checkpoint_lock = threading.Lock()
    print_lock = threading.Lock()
    stop_event = threading.Event()

    if parallel:
        print(f"[INFO] Parallel mode: {len(provider_groups)} provider groups -> {list(provider_groups.keys())}")
    else:
        print(f"[INFO] Sequential mode: 1 provider group")

    try:
        with ThreadPoolExecutor(max_workers=len(provider_groups)) as executor:
            futures = {
                executor.submit(
                    run_group_sequential,
                    group_key, group_run_ids, checkpoints,
                    checkpoint_path, checkpoint_data,
                    checkpoint_lock, print_lock, args,
                    evaluation_methods, allow_duplicates, debug, debug_dir,
                    parallel, stop_event
                ): group_key
                for group_key, group_run_ids in provider_groups.items()
            }
            for future in as_completed(futures):
                group_key = futures[future]
                try:
                    future.result()
                except Exception as e:
                    print(f"[ERROR] Group {group_key} raised an unexpected exception: {e}")
    except KeyboardInterrupt:
        stop_event.set()
        print("\n[INFO] Interrupted by user. Waiting for active runs to finish...")
        sys.exit(0)

    end_time = time.time()

    total_runs_time = sum(
        r.get("elapsed_time", 0)
        for r in checkpoints.values()
        if r.get("status") == "ok"
    )
    h = int(total_runs_time // 3600)
    m = int((total_runs_time % 3600) // 60)
    s = total_runs_time % 60
    print(f"[INFO] Total experiment time (sum of all runs): {h:02d}:{m:02d}:{s:05.2f}")

    print("[INFO] Execution finished. Generating final report...")
    report_dir = os.path.abspath(args.output_dir)

    # Per-run timing + failure list straight from the checkpoint.
    timing_report = []
    failures = []
    baseline_counts: dict = {}
    for rid, r in checkpoints.items():
        if r.get("status") == "ok":
            timing_report.append({
                "run_id": rid,
                "llm": r.get("llm"),
                "total_time": r.get("elapsed_time", 0),
            })
        elif r.get("status") not in ("ok", "pending"):
            failures.append({"run_id": rid, "error": str(r.get("erro") or r.get("status"))})
        baseline = os.path.splitext(os.path.basename(r.get("baseline", "")))[0]
        if baseline:
            baseline_counts[baseline] = baseline_counts.get(baseline, 0) + 1
    run_stats["baseline_counts"] = baseline_counts
    run_stats["total_runs"] = len(checkpoints)

    generate_final_report(
        start_time=start_time,
        end_time=end_time,
        run_stats=run_stats,
        tokens_dir=str(TOKENS_DIR),
        report_dir=report_dir,
        include_metrics_time=True,
        timing_report=timing_report,
        failures=failures,
    )
    print("[INFO] Final report generated.")

    # ─────────────────────────────────────────────────────────────
    # Post-extraction metrics pass: parallel run-level evaluation
    # plus aggregator. Faster than running metrics inside each
    # main.py invocation because transformer models load once per
    # worker instead of once per run.
    # ─────────────────────────────────────────────────────────────
    if not args.skip_metrics and evaluation_methods:
        print("\n[INFO] Running post-extraction metrics pass...")
        metrics_cmd = [
            sys.executable,
            os.path.join(os.path.dirname(__file__), "run_metrics.py"),
            "--root", args.output_dir,
            "--methods", *evaluation_methods,
            "--workers", str(args.metrics_workers),
        ]
        if allow_duplicates:
            metrics_cmd.append("--allow-duplicates")
        try:
            subprocess.run(metrics_cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"[WARNING] Metrics pass exited with {e.returncode}")

    # ─────────────────────────────────────────────────────────────
    # Generate interactive metrics report with PNG export
    # ─────────────────────────────────────────────────────────────
    print("\n[INFO] Generating interactive metrics dashboard and PNG charts...")
    try:
        subprocess.run([
            sys.executable, "-m", "metrics.plot.metrics",
            "--root", args.output_dir,
        ], check=True)

        plot_dir = os.path.abspath(str(PLOTS_DIR))
        if os.path.exists(plot_dir):
            reports = sorted([f for f in os.listdir(plot_dir)
                              if f.startswith('metrics_report_') and f.endswith('.html')])
            if reports:
                latest_report = os.path.join(plot_dir, reports[-1])
                print(f"\n[SUCCESS] Interactive report generated!")
                print(f"[SUCCESS] Open in browser: {latest_report}")
                print(f"[SUCCESS] Total experiment time: {h:02d}:{m:02d}:{s:05.2f}")

    except Exception as e:
        print(f"[WARNING] Failed to generate Plotly report: {e}")
        print("[WARNING] Continuing... (legacy charts still generated)")


if __name__ == "__main__":
    main()
