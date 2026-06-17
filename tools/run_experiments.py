import argparse
import subprocess
import os
import sys
import time
import json
import threading
import shutil
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from mulitaminer.reporting.reporting import generate_final_report
from mulitaminer.utils.gpu_sampler import GpuSampler
from mulitaminer.llm.config_loader import get_provider_key, load_llm
from mulitaminer.configs.constants import RUNS_DIR, DEBUG_DIR, CHECKPOINTS_DIR, PLOTS_DIR, TOKENS_DIR

# Lines from subprocess stdout that are forwarded to the terminal in parallel mode
_PARALLEL_FORWARD = ("[BLOCKS]", "[EXTRACTION]", "[PERFORMANCE]")

# Windows exit code when a process is terminated by Ctrl+C
_CTRL_C_EXIT = 3221225786


def str_to_bool(val):
    return val.lower() in ['true', '1', 'yes', 'sim']


def get_base(filename):
    return os.path.splitext(os.path.basename(filename))[0]


def make_checkpoint_path(ts):
    os.makedirs(CHECKPOINTS_DIR, exist_ok=True)
    return str(CHECKPOINTS_DIR / f"run_checkpoints_{ts}.json")


def execute_run(run_id, run_info, group_key, checkpoints, checkpoint_path,
                checkpoint_data, checkpoint_lock, print_lock, args,
                evaluation_methods, allow_duplicates, parallel, stop_event):
    """Execute a single experiment run as a subprocess."""
    if stop_event.is_set():
        return

    if run_info.get("status") == "ok":
        with print_lock:
            print(f"[SKIP] Run already completed: {run_id}")
        return

    cmd = None
    gpu_sampler = None
    try:
        baseline_path = run_info['baseline']
        extractor_path = run_info['extractor']
        scanner = run_info['scanner']
        llm = run_info['llm']
        run_num = run_info['run_num']
        baseline_name = get_base(baseline_path)
        run_label = f"{llm} run{run_num} | {baseline_name}"

        subdir = os.path.join(args.output_dir, get_base(baseline_path), llm, f"run{run_num}")
        os.makedirs(subdir, exist_ok=True)

        run_prefix = f"{get_base(baseline_path)}_{llm}_run{run_num}"
        output_file = os.path.join(subdir, f"{run_prefix}.txt")
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        cmd = [
            sys.executable, 'main.py',
            '--input', extractor_path,
            '--scanner', scanner,
            '--llm', llm,
            '--output-file', run_prefix,
            '--output-dir', subdir,
            '--baseline-path', baseline_path,
            '--run-experiments',  # suppresses per-run final_report; orchestrator writes one at the end
        ]

        # Metrics are NOT run per-run anymore: a single parallel pass at the end
        # of run_experiments (via run_metrics.py) is faster and avoids reloading
        # transformer models 10× per LLM. evaluation_methods is forwarded to
        # that post-pass instead of being injected here.

        if allow_duplicates:
            cmd.append('--allow-duplicates')

        if args.debug:
            cmd.append('--debug')

        if args.debug_dir != str(DEBUG_DIR):
            cmd += ['--debug-dir', args.debug_dir]

        run_start = time.time()

        # Sample GPU metrics (VRAM peak, energy, util) only for local runs.
        if get_provider_key(llm) == "local":
            gpu_sampler = GpuSampler().start()

        if parallel:
            llm_config = load_llm(llm) or {}
            model_name = llm_config.get("model", llm)
            model_short = model_name.split('/')[-1] if '/' in model_name else model_name
            tok = llm_config.get("tokenizer", {})
            tok_type = tok.get('type', '?') if tok else '?'
            sep = f"[{group_key}] {'─'*52}"
            with print_lock:
                print(
                    f"\n{sep}\n"
                    f"[{group_key}] ▶  {llm} run{run_num}  |  baseline: {baseline_name}\n"
                    f"[{group_key}]    model: {model_short}  |  tokenizer: {tok_type}\n"
                    f"{sep}"
                )
        else:
            print(f"Running extraction + evaluation: {' '.join(cmd)}")

        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, encoding="utf-8", errors="replace") as proc:
            with open(output_file, "w", encoding="utf-8") as f:
                for line in proc.stdout:
                    if not parallel:
                        print(line, end="")
                    else:
                        stripped = line.strip()
                        if any(stripped.startswith(tag) for tag in _PARALLEL_FORWARD):
                            with print_lock:
                                print(f"[{group_key} | {llm}·r{run_num}·{baseline_name}] {stripped}")
                    f.write(line)
            proc.wait()

        if proc.returncode != 0:
            if proc.returncode == _CTRL_C_EXIT:
                stop_event.set()
            raise subprocess.CalledProcessError(proc.returncode, cmd)

        elapsed = time.time() - run_start
        gpu_stats = gpu_sampler.stop() if gpu_sampler else {}

        with checkpoint_lock:
            checkpoints[run_id]["status"] = "ok"
            checkpoints[run_id]["output_file"] = output_file
            checkpoints[run_id]["timestamp"] = timestamp
            checkpoints[run_id]["elapsed_time"] = round(elapsed, 2)
            if gpu_stats:
                checkpoints[run_id].update(gpu_stats)
            checkpoints[run_id]["cmd"] = " ".join(cmd)
            with open(checkpoint_path, "w", encoding="utf-8") as f:
                json.dump(checkpoint_data, f, indent=2, ensure_ascii=False)

        if parallel:
            sep = f"[{group_key}] {'─'*52}"
            with print_lock:
                print(
                    f"[{group_key}] ✓  {run_label}  ({elapsed:.1f}s)\n"
                    f"{sep}\n"
                )
        else:
            print(f"[CHECKPOINT] Saved to {checkpoint_path} after run {run_id}")

    except Exception as e:
        if gpu_sampler:
            gpu_sampler.stop()
        with print_lock:
            if parallel:
                print(f"[{group_key}] -> ERROR: {run_id} -- {e}")
            else:
                print(f"[CHECKPOINT] Error in run {run_id}: {e}")

        with checkpoint_lock:
            checkpoints[run_id]["status"] = "error"
            checkpoints[run_id]["erro"] = str(e)
            checkpoints[run_id]["cmd"] = " ".join(cmd) if cmd else None
            with open(checkpoint_path, "w", encoding="utf-8") as f:
                json.dump(checkpoint_data, f, indent=2, ensure_ascii=False)

        if not parallel:
            print(f"[CHECKPOINT] Saved to {checkpoint_path} after run {run_id}")


def run_group_sequential(group_key, group_run_ids, checkpoints, checkpoint_path,
                         checkpoint_data, checkpoint_lock, print_lock, args,
                         evaluation_methods, allow_duplicates, parallel, stop_event):
    """Run all experiments in a provider group sequentially."""
    for run_id in group_run_ids:
        if stop_event.is_set():
            with print_lock:
                print(f"[{group_key}] -> Stopped (interrupted)")
            break
        run_info = checkpoints[run_id]
        execute_run(
            run_id, run_info, group_key, checkpoints, checkpoint_path,
            checkpoint_data, checkpoint_lock, print_lock, args,
            evaluation_methods, allow_duplicates, parallel, stop_event
        )


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
                        help=('Metrics to run. Available: bert, rouge, entity, schema, severity, '
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
                "input_dir": input_dir,
            }
        }
        with open(checkpoint_path, "w", encoding="utf-8") as f:
            json.dump(checkpoint_data, f, indent=2, ensure_ascii=False)
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
                    evaluation_methods, allow_duplicates, parallel, stop_event
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
