"""Metrics evaluation dispatch.

Owns the registry of metric scripts (which script, which fixed args, in what
order) and the helpers that run them as subprocesses. Imported by the
orchestrator (full pipeline) and by ``tools/run_metrics.py``.
"""
import argparse
import glob
import json
import os
import subprocess
import sys
import time

# Dispatch table for evaluation methods. Each entry is a list:
# ``[script_path, *fixed_args]``. The fixed args are appended after the
# common ones (--baseline-file etc.) and let us route ``bert`` and ``rouge``
# to the unified pipeline with the right ``--scorer`` without keeping
# wrapper scripts around. Adding a new pipeline = one new entry here.
_UNIFIED = os.path.join('metrics', 'pipelines', 'compare_extractions.py')
METRIC_SCRIPTS: dict[str, list[str]] = {
    'bert':     [_UNIFIED, '--scorer', 'bertscore'],
    'rouge':    [_UNIFIED, '--scorer', 'rouge_l'],
    'token_f1': [_UNIFIED, '--scorer', 'token_f1'],
    'field_f1':   [os.path.join('metrics', 'field_f1',  'field_f1.py')],
    'schema':   [os.path.join('metrics', 'pipelines', 'schema_check.py')],
    'severity': [os.path.join('metrics', 'pipelines', 'confusion_severity.py')],
    'coverage': [os.path.join('metrics', 'pipelines', 'coverage.py')],
}

# Order used when the user requests ``all``. Schema runs first (operates on
# the raw JSON, no dependencies); bert/rouge/token_f1 produce the matched
# pairs that field_f1, severity and coverage metrics consume.
ALL_METHODS_ORDER: list[str] = ['schema', 'bert', 'rouge', 'token_f1', 'field_f1', 'severity', 'coverage']

# Methods that need a bert_comparison_*.xlsx or rouge_comparison_*.xlsx
# already in the run directory before they execute.
_DEPS_ON_PAIRS: set[str] = {'field_f1', 'severity', 'coverage'}


def expand_evaluation_methods(methods: list[str]) -> list[str]:
    """Resolve the user's request into a canonical execution list.

    Behaviour:
        * ``'all'`` expands to every registered method.
        * Unknown methods are warned and dropped.
        * If any consumer (``field_f1``/``severity``/``paper``) is requested
          without a producer (``bert``/``rouge``) being part of the list,
          ``bert`` is auto-added so the consumer has matched pairs to read.
        * The returned list is ordered by :data:`ALL_METHODS_ORDER`,
          regardless of the order the user passed — this guarantees that
          producers run before consumers even when the input is unordered.
    """
    requested: set[str] = set()
    for m in methods:
        if m == 'all':
            requested.update(ALL_METHODS_ORDER)
        elif m in METRIC_SCRIPTS:
            requested.add(m)
        else:
            print(f"[WARN] Unknown evaluation method: {m} (skipping)")

    if (requested & _DEPS_ON_PAIRS) and not (requested & {'bert', 'rouge'}):
        print("[INFO] Auto-adding 'bert' because field_f1/severity/coverage need matched pairs.")
        requested.add('bert')

    return [m for m in ALL_METHODS_ORDER if m in requested]


def run_evaluation_method(args: argparse.Namespace, extraction_output_path: str, method: str):
    """
    Run metrics evaluation script as separate process.

    Args:
        args: Command line arguments containing --baseline_path and --llm
        extraction_output_path: Path to generated .xlsx extraction file
        method: Evaluation method to run (key in METRIC_SCRIPTS)
    """
    print(f"\n{'='*60}")
    print(f"[METRICS] Evaluating with: {method.upper()}")
    print(f"{'='*60}")

    entry = METRIC_SCRIPTS.get(method)
    if entry is None:
        print(f"[ERROR] Unknown evaluation method: {method}")
        return

    script_path, *fixed_args = entry
    if not os.path.isfile(script_path):
        print(f"Error: Evaluation script not found at '{script_path}'")
        return

    # Save metrics in the same folder as the extraction results
    output_dir = os.path.dirname(extraction_output_path)

    command = [
        sys.executable,
        script_path,
        '--baseline-file', args.baseline_path,
        '--extraction-file', extraction_output_path,
        '--output-dir', output_dir,
        *fixed_args,
    ]

    # Pass LLM model name to metrics script
    if hasattr(args, 'llm') and args.llm:
        command += ['--llm', args.llm]
    elif hasattr(args, 'llm_config_path') and args.llm_config_path:
        with open(args.llm_config_path, 'r') as f:
            llm_config = json.load(f)
        command += ['--llm', llm_config.get('model', 'unknown')]

    if hasattr(args, 'allow_duplicates') and args.allow_duplicates:
        command += ['--allow-duplicates']

    try:
        subprocess.run(command, check=True)
        print(f"[METRICS] {method.upper()} evaluation completed")
        print(f"[METRICS] Results: {output_dir}")
    except FileNotFoundError:
        print(f"[ERROR] Python or script not found: {script_path}")
        print("Check if the 'metrics' virtual environment is properly configured.")
    except subprocess.CalledProcessError as e:
        print("[ERROR] Metrics evaluation failed")
        print(f"  Command: {' '.join(e.cmd)}")
        print(f"  Exit Code: {e.returncode}")


def run_metrics_only(args: argparse.Namespace) -> None:
    """Re-run the metrics suite on an existing extraction without calling the LLM.

    Locates the JSON output produced by a previous ``main.py`` run in
    ``--output-dir``, derives or converts a sibling XLSX (needed by the
    metric scripts), and dispatches the same evaluation loop as the full
    pipeline. Idempotent — metric scripts will overwrite their own outputs.
    """
    out_dir = args.output_dir
    # Find candidate JSONs in output_dir (top-level only — metric reports
    # like schema_report_*.json live in subdirs in some layouts but here
    # they are flat; filter them out by name prefix).
    jsons = [
        p for p in glob.glob(os.path.join(out_dir, '*.json'))
        if not os.path.basename(p).startswith(('schema_report', 'coverage_'))
    ]
    if not jsons:
        print(f"[ERROR] --metrics-only: no extraction JSON found in {out_dir}.")
        return
    if len(jsons) > 1:
        print(f"[ERROR] --metrics-only: multiple JSONs in {out_dir}, can't pick one:")
        for p in jsons:
            print(f"  - {p}")
        print("  Tip: keep exactly one, or pass --output-file to disambiguate.")
        return
    json_path = jsons[0]
    print(f"[METRICS-ONLY] Using extraction JSON: {json_path}")

    # Metric scripts read JSON natively (same contract as run_metrics.py).
    methods = expand_evaluation_methods(args.evaluation_methods)
    if 'field_f1' not in methods:
        methods.append('field_f1')
    methods = [m for m in ALL_METHODS_ORDER if m in methods]
    metric_start = time.time()
    for method in methods:
        run_evaluation_method(args, json_path, method)
    print(f"\n[METRICS-ONLY] Done in {time.time() - metric_start:.1f}s")
