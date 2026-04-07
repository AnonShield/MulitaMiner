import os
import sys
import time
# Ensures 'src' directory is in sys.path for absolute imports
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
src_path = os.path.join(project_root, 'src')
if src_path not in sys.path:
    sys.path.insert(0, src_path)
import argparse
import subprocess
from tqdm import tqdm
from utils.cli_args import parse_arguments

def batch_extract_vulnerabilities(input_dir, output_dir=None, marker='_batch', scanner=None, llm=None, convert=None, extra_args=None):
    """
    Executes the vulnerability extraction for all PDFs in the specified input directory and saves results in an output directory.
    """
    input_dir = os.path.abspath(input_dir)
    if not os.path.isdir(input_dir):
        print(f"[ERROR] Directory not found: {input_dir}")
        return

    # Define output directory
    if output_dir is None:
        # Output to current directory with marker suffix
        base = os.path.basename(input_dir.rstrip('/\\'))
        output_dir = f"{base}{marker}"
    os.makedirs(output_dir, exist_ok=True)

    pdf_files = [f for f in os.listdir(input_dir) if f.lower().endswith('.pdf')]
    if not pdf_files:
        print(f"No PDFs found in directory: {input_dir}")
        return

    print(f"Processing {len(pdf_files)} PDFs to {output_dir} ...")
    real_start_time = time.time()
    metric_duration = 0
    for pdf_file in tqdm(pdf_files, desc="Extracting vulnerabilities"):
        pdf_path = os.path.join(input_dir, pdf_file)
        base_name = os.path.splitext(pdf_file)[0]
        output_json = os.path.join(output_dir, f"{base_name}.json")

        cmd = [
            sys.executable, 'main.py',
            '--input', pdf_path,
            '--output-file', os.path.splitext(os.path.basename(pdf_file))[0],
            '--output-dir', output_dir
        ]
        if scanner:
            cmd += ['--scanner', scanner]
        if llm:
            cmd += ['--llm', llm]
        if convert:
            cmd += ['--convert', convert]
        if extra_args:
            cmd += extra_args

        try:
            print(f"\n[INFO] Processing: {pdf_file}")
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to process {pdf_file}: {e}")
    real_end_time = time.time()
    # Generate final modular report
    # Add project root to path for imports
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    from src.utils.reporting import generate_final_report
    run_stats = {
        'start_time': real_start_time,
        'end_time': real_end_time,
        'duration': real_end_time - real_start_time,
        'total_pdfs': len(pdf_files),
        'metric_duration': metric_duration,
    }
    timing_report = [
        {
            'pdfs': len(pdf_files),
            'metric_time': metric_duration,
            'total_time': real_end_time - real_start_time,
        }
    ]
    generate_final_report(
        start_time=real_start_time,
        end_time=real_end_time,
        run_stats=run_stats,
        tokens_dir='results_tokens',
        report_dir=output_dir,
        include_metrics_time=True,
        timing_report=timing_report
    )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Batch PDF Vulnerability Extractor")
    parser.add_argument('--input-dir', required=True, help="Directory containing PDF files to process (path to folder with PDFs)")
    parser.add_argument('--marker', default='_batch', help="Marker for the output directory (default: _batch)")
    parser.add_argument('--output-dir', help="Output directory (optional)")
    parser.add_argument('--scanner', help="Name of the scanner (e.g., tenable, openvas, etc)")
    parser.add_argument('--llm', help="Name of the LLM to use (e.g., gpt4, deepseek, etc)")
    parser.add_argument('--convert', choices=['csv', 'xlsx', 'tsv', 'all', 'none'], help="Convert output to specific format")
    parser.add_argument('--allow-duplicates', action='store_true', help="Allow duplicate vulnerabilities in the output (default: False)")
    args, extra = parser.parse_known_args()
    
    if args.allow_duplicates and '--allow-duplicates' not in extra:
        extra.append('--allow-duplicates')
    batch_extract_vulnerabilities(
        input_dir=args.input_dir,
        output_dir=args.output_dir,
        marker=args.marker,
        scanner=args.scanner,
        llm=args.llm,
        convert=args.convert,
        extra_args=extra
    )
