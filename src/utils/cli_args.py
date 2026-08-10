import argparse

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments for main extraction processing."""
    parser = argparse.ArgumentParser(
        description='Extract vulnerabilities from PDF reports and optionally convert to other formats or evaluate with metrics.'
    )
    # --- Simplified arguments for convenience ---
    parser.add_argument('--input', required=False, help='Path to input PDF file (required unless --metrics-only)')
    parser.add_argument('--scanner', default='default', 
                       help='Scanner profile name (e.g., "openvas"). Loads the corresponding .json from src/configs/scanners/.')
    parser.add_argument('--llm', default='gpt4', 
                       help='LLM configuration name (e.g., "llama3"). Loads the corresponding .json from src/configs/llms/.')
    
    # Conversion options group
    conversion_group = parser.add_argument_group('Conversion & Output Options')
    conversion_group.add_argument('--output-file', help='Output filename without extension (e.g., "my_extraction"). Default: PDF name.')
    conversion_group.add_argument('--output-dir', default='.', help='Output directory for results (default: current directory).')
    conversion_group.add_argument('--convert', choices=['csv', 'xlsx', 'tsv', 'all'],
                       default=None,
                       help='Optionally convert the JSON output to an additional format. Omit to keep only JSON (the native output that metrics consume directly).')
    conversion_group.add_argument('--md', dest='use_markdown', action='store_true',
                       help='Use Markdown format for PDF text extraction instead of plain text (default: False)')
    conversion_group.add_argument('--csv-delimiter', dest='csv_delimiter', default=',',
                       help='Delimiter for CSV (default: ,)')
    conversion_group.add_argument('--csv-encoding', dest='csv_encoding', default='utf-8-sig',
                       help='Encoding for CSV (default: utf-8-sig)')

    # Metric evaluation options group
    evaluation_group = parser.add_argument_group('Metric Evaluation Options')
    evaluation_group.add_argument('--baseline-path', dest='baseline_path', type=str,
                                 help='Path to the .xlsx ground truth file for comparison. Required if --evaluation-methods is used.')
    evaluation_group.add_argument('--metrics', dest='evaluation_methods',
                                 nargs='+', default=[],
                                 help=('Metrics to run. Available: bert, rouge, entity, schema, '
                                       'severity, coverage. Use "all" for every method. Producer/consumer '
                                       'dependencies are auto-resolved. Example: --metrics all'))
    evaluation_group.add_argument('--allow-duplicates', dest='allow_duplicates', action='store_true',
                                 help='Allow legitimate duplicates in baseline during evaluation (default: False)')
    evaluation_group.add_argument('--metrics-only', dest='metrics_only', action='store_true',
                                 help=('Skip PDF extraction and run metrics on an existing JSON in --output-dir. '
                                       'Use after fixing a baseline / tweaking a metric pipeline / re-comparing. '
                                       'Requires --output-dir to contain exactly one *.json from a prior main.py run.'))
    
    # Debug options group
    debug_group = parser.add_argument_group('Debug Options')
    debug_group.add_argument('--debug', dest='debug', action='store_true',
                           help='Enable debug logging of raw LLM responses (saves to llm_debug_responses/). Note: increases disk I/O (default: False)')
    debug_group.add_argument('--debug-dir', dest='debug_dir', default='llm_debug_responses',
                           help='Directory for debug logs (default: llm_debug_responses)')
    
    # Internal flag for experiment script
    parser.add_argument('--run-experiments', action='store_true', help=argparse.SUPPRESS) # Hide from help
    
    return parser.parse_args()
