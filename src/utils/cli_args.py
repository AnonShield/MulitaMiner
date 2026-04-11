import argparse

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments for main extraction processing."""
    parser = argparse.ArgumentParser(
        description='Extract vulnerabilities from PDF reports and optionally convert to other formats or evaluate with metrics.'
    )
    # --- Simplified arguments for convenience ---
    parser.add_argument('--input', required=True, help='Path to input PDF file')
    parser.add_argument('--scanner', default='default', 
                       help='Scanner profile name (e.g., "openvas"). Loads the corresponding .json from src/configs/scanners/.')
    parser.add_argument('--llm', default='gpt4', 
                       help='LLM configuration name (e.g., "llama3"). Loads the corresponding .json from src/configs/llms/.')
    
    # Conversion options group
    conversion_group = parser.add_argument_group('Conversion & Output Options')
    conversion_group.add_argument('--output-file', help='Output filename without extension (e.g., "my_extraction"). Default: PDF name.')
    conversion_group.add_argument('--output-dir', default='.', help='Output directory for results (default: current directory).')
    conversion_group.add_argument('--convert', choices=['csv', 'xlsx', 'tsv', 'all', 'none'],
                       default='xlsx',
                       help='Convert JSON output to a specific format. Use "all" or "xlsx" for evaluation (default: xlsx).')
    conversion_group.add_argument('--csv-delimiter', dest='csv_delimiter', default=',',
                       help='Delimiter for CSV (default: ,)')
    conversion_group.add_argument('--csv-encoding', dest='csv_encoding', default='utf-8-sig',
                       help='Encoding for CSV (default: utf-8-sig)')

    # Metric evaluation options group
    evaluation_group = parser.add_argument_group('Metric Evaluation Options')
    evaluation_group.add_argument('--baseline-path', dest='baseline_path', type=str,
                                 help='Path to the .xlsx ground truth file for comparison. Required if --evaluation-methods is used.')
    evaluation_group.add_argument('--evaluation-methods', dest='evaluation_methods', nargs='+', 
                                 choices=['bert', 'rouge'], default=[],
                                 help='Evaluation methods to run. Entity metrics are automatically included. Example: bert rouge')
    evaluation_group.add_argument('--allow-duplicates', dest='allow_duplicates', action='store_true',
                                 help='Allow legitimate duplicates in baseline during evaluation (default: False)')
    
    # Debug options group
    debug_group = parser.add_argument_group('Debug Options')
    debug_group.add_argument('--debug', dest='debug', action='store_true',
                           help='Enable debug logging of raw LLM responses (saves to llm_debug_responses/). Note: increases disk I/O (default: False)')
    debug_group.add_argument('--debug-dir', dest='debug_dir', default='llm_debug_responses',
                           help='Directory for debug logs (default: llm_debug_responses)')
    
    # Internal flag for experiment script
    parser.add_argument('--run-experiments', action='store_true', help=argparse.SUPPRESS) # Hide from help
    
    return parser.parse_args()
