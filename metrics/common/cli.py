import argparse
import os
from pathlib import Path

def parse_arguments_common(require_model: bool = False):
    """
    Standard parser for metric scripts (bert, rouge, etc).
    Args:
        require_model: if True, require the --model argument.
    Returns:
        argparse.Namespace with the arguments.
    """
    parser = argparse.ArgumentParser(
        description='Compare extractions with baseline using metrics.'
    )
    parser.add_argument('--baseline-file', dest='baseline_file', type=str, required=True,
                       help='Path to baseline Excel file')
    parser.add_argument('--extraction-file', dest='extraction_file', type=str, required=True,
                       help='Path to Excel file with extractions')
    parser.add_argument('--output-dir', dest='output_dir', type=str, required=False,
                       help='Directory to save results (optional, default: metrics/<metric>/results/)')
    parser.add_argument('--model', type=str, required=require_model, default=None,
                       help='LLM model name used (optional, but recommended for naming output file)')
    parser.add_argument('--allow-duplicates', dest='allow_duplicates', action='store_true',
                       help='Allow legitimate duplicates in baseline during evaluation')
    args = parser.parse_args()
    # Basic validation
    if not os.path.isfile(args.baseline_file):
        parser.error(f"Baseline file not found: {args.baseline_file}")
    if not os.path.isfile(args.extraction_file):
        parser.error(f"Extraction file not found: {args.extraction_file}")
    # If not specified, set default directory based on metric detected by script name
    if not args.output_dir:
        import sys
        script_name = Path(sys.argv[0]).name.lower()
        if 'bert' in script_name:
            args.output_dir = str(Path('metrics/bert/results'))
        elif 'rouge' in script_name:
            args.output_dir = str(Path('metrics/rouge/results'))
        else:
            args.output_dir = str(Path('metrics/results'))
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    return args
