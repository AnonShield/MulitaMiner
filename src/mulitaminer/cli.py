"""Command-line entry point: parse, validate, dispatch.

``python main.py ...`` is a thin wrapper around :func:`main`, which parses the
arguments, validates them, and dispatches to either the metrics-only path or
the full extraction pipeline.
"""
import argparse
import io
import os
import sys

from mulitaminer.cli_args import parse_arguments
from mulitaminer.pipeline.orchestrator import run_extraction
from mulitaminer.pipeline.metrics_dispatch import run_metrics_only

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')


def validate_inputs(args: argparse.Namespace) -> bool:
    """Validate user input arguments and required files."""
    if getattr(args, 'metrics_only', False):
        # In metrics-only mode the PDF is irrelevant — we never read it. The
        # output dir + baseline are the only hard requirements.
        if not args.output_dir or not os.path.isdir(args.output_dir):
            print(f"Error: --metrics-only requires an existing --output-dir; got: {args.output_dir}")
            return False
        if not args.evaluation_methods:
            print("Error: --metrics-only requires --metrics ... to know what to evaluate.")
            return False
        if not args.baseline_path or not os.path.isfile(args.baseline_path):
            print(f"Error: --metrics-only requires a valid --baseline-path; got: {args.baseline_path}")
            return False
        return True
    if not args.input or not os.path.isfile(args.input):
        print(f"Error: PDF file not found: {args.input}")
        return False
    # If evaluation methods are specified, baseline is required
    if args.evaluation_methods:
        if not args.baseline_path:
            print("Error: The --baseline-path argument is required when --evaluation-methods is used.")
            return False
        if not os.path.isfile(args.baseline_path):
            print(f"Error: Baseline file not found: {args.baseline_path}")
            return False
    return True


def main():
    """Parse args, validate, and dispatch to the right pipeline path."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--run-experiments', action='store_true', help='Batch run mode indicator from run_experiments.py')
    known_args, _ = parser.parse_known_args()
    args = parse_arguments()
    args.run_experiments = getattr(known_args, 'run_experiments', False)

    if not validate_inputs(args):
        return

    # --metrics-only short-circuit: skip extraction, run metrics on the
    # existing JSON in --output-dir. Used after fixing a baseline or changing
    # a metric pipeline — no LLM call, no API cost.
    if getattr(args, 'metrics_only', False):
        run_metrics_only(args)
        return

    run_extraction(args)
