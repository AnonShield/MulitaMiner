import os
import sys
# Garante que o diretório 'src' esteja no sys.path para imports absolutos
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
    Executa a extração de vulnerabilidades em lote, chamando main.py para cada PDF.
    """
    input_dir = os.path.abspath(input_dir)
    if not os.path.isdir(input_dir):
        print(f"[ERRO] Diretório não encontrado: {input_dir}")
        return

    # Define diretório de saída
    if output_dir is None:
        parent = os.path.dirname(input_dir)
        base = os.path.basename(input_dir)
        output_dir = os.path.join(parent, f"{base}{marker}")
    os.makedirs(output_dir, exist_ok=True)

    pdf_files = [f for f in os.listdir(input_dir) if f.lower().endswith('.pdf')]
    if not pdf_files:
        print(f"No PDFs found in directory: {input_dir}")
        return

    print(f"Processing {len(pdf_files)} PDFs to {output_dir} ...")
    for pdf_file in tqdm(pdf_files, desc="Extracting vulnerabilities"):
        pdf_path = os.path.join(input_dir, pdf_file)
        base_name = os.path.splitext(pdf_file)[0]
        output_json = os.path.join(output_dir, f"{base_name}.json")

        cmd = [
            sys.executable, 'main.py', pdf_path,
            '--output', output_json,
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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Batch PDF Vulnerability Extractor")
    parser.add_argument('input_dir', help="Directory containing PDF files to process (path to folder with PDFs)")
    parser.add_argument('--marker', default='_batch', help="Marker for the output directory (default: _batch)")
    parser.add_argument('--output-dir', help="Output directory (optional)")
    parser.add_argument('--scanner', help="Name of the scanner (e.g., tenable, openvas, etc)")
    parser.add_argument('--llm', help="Name of the LLM to use (e.g., gpt4, deepseek, etc)")
    parser.add_argument('--convert', choices=['csv', 'xlsx', 'tsv', 'all', 'none'], help="Convert output to specific format")
    parser.add_argument('--allow-duplicates', action='store_true', help="Allow duplicate vulnerabilities in the output (default: False)")
    args, extra = parser.parse_known_args()
    # Garante que --allow-duplicates seja repassado explicitamente ao main.py
    if args.allow_duplicates and '--allow-duplicates' not in extra:
        extra.append('--allow-duplicates')
    batch_extract_vulnerabilities(
        args.input_dir,
        output_dir=args.output_dir,
        marker=args.marker,
        scanner=args.scanner,
        llm=args.LLM,
        convert=args.convert,
        extra_args=extra
    )
