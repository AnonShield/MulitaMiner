"""Experiment runner: execute one run as a subprocess, with GPU sampling,
checkpointing and provider-group threading. Driven by tools/run_experiments.py.
"""
import os
import subprocess
import sys
import time
from datetime import datetime

from mulitaminer.llm.config_loader import get_provider_key, load_llm
from mulitaminer.utils.gpu_sampler import GpuSampler
from mulitaminer.configs.constants import DEBUG_DIR
from mulitaminer.experiments.checkpoint import save_checkpoint

# Lines from subprocess stdout that are forwarded to the terminal in parallel mode
_PARALLEL_FORWARD = ("[BLOCKS]", "[EXTRACTION]", "[PERFORMANCE]")

# Windows exit code when a process is terminated by Ctrl+C
_CTRL_C_EXIT = 3221225786


def get_base(filename):
    return os.path.splitext(os.path.basename(filename))[0]


def execute_run(run_id, run_info, group_key, checkpoints, checkpoint_path,
                checkpoint_data, checkpoint_lock, print_lock, args,
                evaluation_methods, allow_duplicates, debug, debug_dir,
                parallel, stop_event):
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

        if debug:
            cmd.append('--debug')

        if debug_dir != str(DEBUG_DIR):
            cmd += ['--debug-dir', debug_dir]

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

        # PYTHONUNBUFFERED=1 keeps the child line-buffered so its progress
        # streams in real time (and interleaves correctly in parallel mode).
        env = {**os.environ, "PYTHONUNBUFFERED": "1"}
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, encoding="utf-8", errors="replace", env=env) as proc:
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
            save_checkpoint(checkpoint_path, checkpoint_data)

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
            save_checkpoint(checkpoint_path, checkpoint_data)

        if not parallel:
            print(f"[CHECKPOINT] Saved to {checkpoint_path} after run {run_id}")


def run_group_sequential(group_key, group_run_ids, checkpoints, checkpoint_path,
                         checkpoint_data, checkpoint_lock, print_lock, args,
                         evaluation_methods, allow_duplicates, debug, debug_dir,
                         parallel, stop_event):
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
            evaluation_methods, allow_duplicates, debug, debug_dir,
            parallel, stop_event
        )
