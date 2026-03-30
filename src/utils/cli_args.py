import argparse

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments for main extraction processing."""
    parser = argparse.ArgumentParser(
        description='Extract vulnerabilities from PDF reports and optionally convert to other formats or evaluate with metrics.'
    )
    # Grupo principal de argumentos
    parser.add_argument('--input', required=True, help='Path to input PDF file')
    parser.add_argument('--scanner', default='default', 
                       help='Scanner name to use (default: default)')
    parser.add_argument('--llm', default='gpt4', 
                       help='LLM name to use (default: gpt4)')
    
    # Conversion options group
    conversion_group = parser.add_argument_group('Conversion Options')
    conversion_group.add_argument('--convert', choices=['csv', 'xlsx', 'tsv', 'all', 'none'],
                       default='none',
                       help='Convert JSON output to a specific format. Use "all" or "xlsx" for evaluation.')
    conversion_group.add_argument('--output-file', help='Name of the output file (without timestamp/id, without required extension)')
    conversion_group.add_argument('--output-dir', dest='output_dir',
                       help='Directory for converted files')
    conversion_group.add_argument('--csv-delimiter', dest='csv_delimiter', default=',',
                       help='Delimiter for CSV (default: ,)')
    conversion_group.add_argument('--csv-encoding', dest='csv_encoding', default='utf-8-sig',
                       help='Encoding for CSV (default: utf-8-sig)')

    # Metric evaluation options group
    evaluation_group = parser.add_argument_group('Metric Evaluation Options')
    evaluation_group.add_argument('--evaluate', action='store_true',
                                 help='Activate evaluation mode to compare extractions with a baseline using metrics.')
    evaluation_group.add_argument('--baseline', type=str,
                                 help='Path to the .xlsx ground truth file for comparison.')
    evaluation_group.add_argument('--evaluation-method', choices=['bert', 'rouge'], default='bert',
                                 help='Evaluation method to be used (default: bert).')
    evaluation_group.add_argument('--allow-duplicates', dest='allow_duplicates', action='store_true',
                                 help='Allow legitimate duplicates in baseline during evaluation (default: False)')
    evaluation_group.add_argument('--run-experiments', action='store_true',
                                 help='Indicates batch execution (run_experiments.py) to save files in results_runs.')
    
    return parser.parse_args()
