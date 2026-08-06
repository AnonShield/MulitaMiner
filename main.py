"""
PDF Vulnerability Extractor - Main Entry Point

Extract vulnerabilities from PDF reports (OpenVAS/Tenable WAS) using LLM
and convert to structured formats (JSON/CSV/XLSX).

Usage:
    python main.py --input <pdf_path> [--llm <model>] [--convert <format>] [--scanner <name>]
"""
import os
import sys
import argparse
import json
import subprocess
import datetime
import time
import glob
import shutil
import io
from tqdm import tqdm

from src.utils.block_creation import create_session_blocks_from_text, extract_vulns_from_blocks, cleanup_temp_blocks
from src.utils.cli_args import parse_arguments
from src.utils.pdf_loader import save_visual_layout
from src.utils.extractors import get_extractor
from src.utils import pdf_loader, block_creation
from src.model_management import load_profile, load_llm, init_llm, validate_and_normalize_vulnerability
from src.converters import execute_conversions
from src.utils.cais_validator import validate_cais_vulnerability

from src.utils.chunking import get_token_based_chunks
from src.scanner_strategies.consolidation import central_custom_allow_duplicates
from src.utils.profile_registry import is_cais_profile
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

project_root = os.path.abspath(os.path.dirname(__file__))
src_path = os.path.join(project_root, 'src')
if src_path not in sys.path:
    sys.path.insert(0, src_path)

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')


def get_validator(profile_config: dict):
    """Get validator function based on profile configuration."""
    if is_cais_profile(profile_config):
        return validate_cais_vulnerability
    return validate_and_normalize_vulnerability


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


def load_configs(args: argparse.Namespace) -> tuple:
    """Load profile and LLM configuration from files."""
    profile_config = load_profile(args.scanner)
    if not profile_config:
        print(f"Error: Could not load profile configuration for '{args.scanner}'.")
        return None, None

    llm_config = load_llm(args.llm)
    if not llm_config:
        print(f"Error: Could not load LLM configuration for '{args.llm}'.")
        return None, None
        
    return profile_config, llm_config


def save_results(vulnerabilities: list, output_file: str, profile_config: dict = None, allow_duplicates: bool = False) -> dict:
    """
    Save vulnerabilities to JSON file.
    
    Args:
        vulnerabilities: List of vulnerabilities
        output_file: Path to output file
        profile_config: Optional profile configuration
        allow_duplicates: Whether to allow duplicate entries
    
    Returns:
        Dictionary with status and counts: {'success': bool, 'extracted': int, 'after_consolidation': int, 'final': int}
    """
    try:
        print(f"\n[PROCESSING] Consolidating vulnerabilities (allow_duplicates={allow_duplicates})")
        final_vulns = central_custom_allow_duplicates(vulnerabilities, profile_config, allow_duplicates, output_file=output_file)
        after_consolidation_count = len(final_vulns) if final_vulns else 0
        if not final_vulns:
            print(f"\n[EXTRACTION] No vulnerabilities found.")
        
        def has_valid_description(vuln):
            """Check if vulnerability has valid description field."""
            desc = vuln.get("description")
            if not desc:
                return False
            if isinstance(desc, list):
                return any(str(d).strip() for d in desc)
            return bool(str(desc).strip())

        def has_valid_name(vuln):
            """Check if vulnerability has valid Name field."""
            name = vuln.get("Name")
            if not name:
                return False
            return bool(str(name).strip())

        def is_valid(vuln):
            return has_valid_name(vuln) and has_valid_description(vuln)

        removed_vulns = [v for v in final_vulns if not is_valid(v)]
        final_vulns = [v for v in final_vulns if is_valid(v)]
        
        if removed_vulns:
            log_path = os.path.splitext(output_file)[0] + '_removed_log.txt'
            with open(log_path, 'w', encoding='utf-8') as logf:
                logf.write(
                    "VULNERABILITY REMOVAL LOG\n"
                    "This file lists all vulnerabilities removed due to lack of valid Name or description.\n"
                    "Each item presents relevant details for traceability.\n\n"
                )
                logf.write(f"Total vulnerabilities removed: {len(removed_vulns)}\n\n")
                for idx, v in enumerate(removed_vulns, 1):
                    name = str(v.get('Name', 'NO NAME'))
                    port = str(v.get('port', ''))
                    protocol = str(v.get('protocol', ''))
                    severity = str(v.get('severity', ''))
                    logf.write(f"{idx}. Name: {name}\n")
                    logf.write(f"   Port: {port} | Protocol: {protocol} | Severity: {severity}\n")
                    desc = v.get('description', '')
                    if desc:
                        if isinstance(desc, list):
                            desc = ' '.join([str(d) for d in desc if d])
                        desc = str(desc).strip().replace('\n', ' ')
                        logf.write(f"   Original description (invalid): {desc[:200]}{'...' if len(desc)>200 else ''}\n")
                    logf.write("\n")
                logf.write(f"Final summary: {len(removed_vulns)} vulnerabilities removed due to lack of valid Name or description.\n")
            print(f"[REMOVED] Invalid entries filtered: {len(removed_vulns)}")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(final_vulns, f, indent=2, ensure_ascii=False)
        
        print("\n" + "="*60)
        print("[SUMMARY] EXTRACTION COMPLETE")
        print("="*60)
        print(f"Output file: {output_file}")
        print(f"Final vulnerabilities: {len(final_vulns)}")
        if removed_vulns:
            print(f"  (removed {len(removed_vulns)} invalid)")
        print("="*60 + "\n")
        
        return {
            'success': True,
            'extracted': len(vulnerabilities),
            'after_consolidation': after_consolidation_count,
            'final': len(final_vulns)
        }
    except Exception as e:
        print(f"Error saving JSON: {e}")
        return {
            'success': False,
            'extracted': len(vulnerabilities) if vulnerabilities else 0,
            'after_consolidation': 0,
            'final': 0
        }


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
    'entity':   [os.path.join('metrics', 'entity',    'compare_extractions_entity.py')],
    'schema':   [os.path.join('metrics', 'pipelines', 'schema_check.py')],
    'severity': [os.path.join('metrics', 'pipelines', 'confusion_severity.py')],
    'coverage': [os.path.join('metrics', 'pipelines', 'coverage.py')],
}

# Order used when the user requests ``all``. Schema runs first (operates on
# the raw JSON, no dependencies); bert/rouge/token_f1 produce the matched
# pairs that entity, severity and coverage metrics consume.
ALL_METHODS_ORDER: list[str] = ['schema', 'bert', 'rouge', 'token_f1', 'entity', 'severity', 'coverage']

# Methods that need a bert_comparison_*.xlsx or rouge_comparison_*.xlsx
# already in the run directory before they execute.
_DEPS_ON_PAIRS: set[str] = {'entity', 'severity', 'coverage'}


def expand_evaluation_methods(methods: list[str]) -> list[str]:
    """Resolve the user's request into a canonical execution list.

    Behaviour:
        * ``'all'`` expands to every registered method.
        * Unknown methods are warned and dropped.
        * If any consumer (``entity``/``severity``/``paper``) is requested
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
        print("[INFO] Auto-adding 'bert' because entity/severity/coverage need matched pairs.")
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


def _run_metrics_only(args: argparse.Namespace) -> None:
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
    if 'entity' not in methods:
        methods.append('entity')
    methods = [m for m in ALL_METHODS_ORDER if m in methods]
    metric_start = time.time()
    for method in methods:
        run_evaluation_method(args, json_path, method)
    print(f"\n[METRICS-ONLY] Done in {time.time() - metric_start:.1f}s")


def _report_api_failure(exc: BaseException, llm_name: str) -> None:
    """Print an actionable message for provider errors instead of a raw traceback."""
    from src.utils.chunking import _is_fatal_api_error

    msg = str(exc)
    print(f"\n{'-' * 60}")
    if _is_fatal_api_error(exc):
        low = msg.lower()
        if any(k in low for k in ("401", "authentication", "invalid_api_key", "incorrect api key")):
            reason = f"the API key for '{llm_name}' was rejected (invalid or expired)"
            hint = "Check the key in your .env file; see .env.example for the expected name."
        elif any(k in low for k in ("quota", "429", "rate limit", "ratelimit")):
            reason = f"the provider refused the request for '{llm_name}' (quota or rate limit)"
            hint = "Wait and retry, or use a key with remaining quota."
        else:
            reason = f"the provider rejected the request for '{llm_name}'"
            hint = "Check the key and the endpoint in src/configs/llms/."
        print(f"[ERROR] Extraction aborted: {reason}.")
        print(f"        {hint}")
    else:
        print(f"[ERROR] Extraction aborted: {type(exc).__name__}: {msg}")
    print(f"        Provider message: {msg.strip()[:300]}")
    print(f"{'-' * 60}")


def main():
    """Main extraction pipeline entry point."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--run-experiments', action='store_true', help='Batch run mode indicator from run_experiments.py')
    known_args, _ = parser.parse_known_args()
    args = parse_arguments()
    args.run_experiments = getattr(known_args, 'run_experiments', False)
    
    if not validate_inputs(args):
        return
    real_start_time = time.time()

    # ────────────────────────────────────────────────────────────────────
    # --metrics-only short-circuit: skip extraction, run metrics on the
    # existing JSON in --output-dir. Used after fixing a baseline or
    # changing a metric pipeline — no LLM call, no API cost.
    # ────────────────────────────────────────────────────────────────────
    if getattr(args, 'metrics_only', False):
        _run_metrics_only(args)
        return

    profile_config, llm_config = load_configs(args)
    if not profile_config or not llm_config:
        return

    llm = init_llm(llm_config)
    
    if 'max_completion_tokens' in llm_config:
        max_tokens = llm_config.get('max_completion_tokens', 4096)
    elif llm_config.get('provider') == 'ollama' and 'options' in llm_config:
        max_tokens = llm_config['options'].get('num_ctx', 4096)
    else:
        max_tokens = llm_config.get('max_tokens', 4096)
    
    if max_tokens is None:
        max_tokens = 4096
    max_tokens = int(max_tokens)
    
    reserve_response = llm_config.get('reserve_for_response', 1000)
    if reserve_response is None:
        reserve_response = 1000
    reserve_response = int(reserve_response)
    
    print(f"\n{'='*60}")
    print(f"[CONFIG] LLM: {llm_config.get('model')}")
    print(f"[CONFIG] Max tokens: {max_tokens}")
    print(f"[CONFIG] Reserve for response: {reserve_response}")
    print(f"{'='*60}\n")

    # Extração do PDF com layout visual
    print(f"[PDF] Loading PDF from: {args.input}")
    
    extractor = get_extractor(getattr(args, 'use_markdown', False))
    print(f"[PDF] Using extractor: {extractor.__class__.__name__}")
    result = extractor.extract(args.input, args.scanner)

    if result is None:
        print("[ERROR] No text could be extracted from the PDF.")
        return

    output_ext = result.output_ext

    # Salvar layout visual a partir do sumário (necessário para estratégias
    # que requerem contexto visual, como OpenVAS). Lives in output_dir so it
    # doesn't pollute the project root.
    # Cached at the project root (visual_layouts/<baseline>.<ext>) — same PDF
    # gives the same layout, so we share across runs.
    visual_file = save_visual_layout(
        result.summary.page_content, args.input,
        output_ext=output_ext, output_dir=args.output_dir,
    )
    print(f"[LAYOUT] Visual layout: {visual_file}")

    extraction_text = result.extraction.page_content

    # Texto bruto da extração — útil para inspeção, mas só persiste com --debug
    # para não criar lixo na raiz do projeto em runs normais.
    if args.debug:
        pdf_base_name = os.path.splitext(os.path.basename(args.input))[0]
        extraction_file = os.path.join(args.output_dir, f"extraction_{pdf_base_name}.{output_ext}")
        try:
            os.makedirs(args.output_dir, exist_ok=True)
            with open(extraction_file, 'w', encoding='utf-8') as f:
                f.write(extraction_text)
            print(f"[EXTRACTION] Full extraction saved: {extraction_file}")
        except Exception as e:
            print(f"[WARN] Could not save extraction file: {e}")

    # Criação de blocos de sessão com nome único para paralelismo (PRECISA do LLM)
    unique_process_id = args.llm
    temp_dir = f'temp_blocks_{unique_process_id}'
    session_blocks = create_session_blocks_from_text(
        extraction_text,
        temp_dir=temp_dir,
        visual_layout_path=visual_file,
        scanner=args.scanner,
        output_ext=output_ext
    )
    print(f"[BLOCKS] {len(session_blocks)} session blocks created")

    # Se nenhum bloco for criado, interrompe a execução para evitar erros
    if not session_blocks:
        print("[ERROR] No session blocks were created. Aborting.")
        return

    # Processamento dos blocos
    pdf_filename = os.path.basename(args.input)
    pdf_name = os.path.splitext(pdf_filename)[0]  # Remove extension
    llm_name = args.llm
    debug_mode = getattr(args, 'debug', False)
    debug_dir = getattr(args, 'debug_dir', 'llm_debug_responses')
    
    try:
        all_vulnerabilities = extract_vulns_from_blocks(
            session_blocks, llm, profile_config, get_token_based_chunks, llm_config=llm_config,
            pdf_name=pdf_name, llm_name=llm_name, debug_mode=debug_mode
        )
    except Exception as exc:
        cleanup_temp_blocks(temp_dir=temp_dir)
        _report_api_failure(exc, args.llm)
        sys.exit(1)
    total_chunks = len(session_blocks)

    cleanup_temp_blocks(temp_dir=temp_dir)

    print(f"\n{'-'*60}")
    print(f"[EXTRACTION] Total blocks processed: {total_chunks}")
    print(f"{'-'*60}")

    run_prefix = os.environ.get("RUN_PREFIX")
    
    # Determine output directory and file
    output_dir = args.output_dir if args.output_dir else '.'
    os.makedirs(output_dir, exist_ok=True)
    
    # Determine output filename
    if args.output_file:
        output_base = args.output_file
    else:
        # Fallback: use PDF name + LLM name + timestamp
        pdf_base = os.path.splitext(os.path.basename(args.input))[0]
        llm_name = llm_config.get('model', 'unknown').replace('/', '_').replace(':', '_')
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_base = f"{pdf_base}_{llm_name}_{timestamp}"
    
    # Build full output path for JSON
    output_file = os.path.join(output_dir, f"{output_base}.json")

    save_result = save_results(all_vulnerabilities, output_file, profile_config, getattr(args, 'allow_duplicates', False))
    extracted_count = save_result['extracted']
    after_consolidation_count = save_result['after_consolidation']
    final_vuln_count = save_result['final']
    
    xlsx_output_path = None
    
    if save_result['success']:
        # Handle token log file renaming
        pid = os.getpid()
        tokens_candidates = glob.glob(f'results_tokens/tokens_info_{pid}.json')
        if tokens_candidates:
            llm_name = llm_config.get('model', 'unknown').replace('/', '_').replace(':', '_')
            tokens_final_name = f"{output_base}_{llm_name}_tokens.json"
            tokens_final_path = os.path.join('results_tokens', tokens_final_name)
            
            # Ensure the directory exists
            os.makedirs('results_tokens', exist_ok=True)
            
            shutil.move(tokens_candidates[0], tokens_final_path)
            print(f"[TOKENS] Token file saved at: {tokens_final_path}")

        # Handle conversions — JSON is the native output and metrics consume
        # it directly, so we no longer force xlsx. Honor exactly what the
        # user asked for via --convert (default: none).
        try:
            converted_files = execute_conversions(output_file, args)
            if converted_files:
                print(f"\n[CONVERSIONS] Generated {len(converted_files)} format(s):")
                for c in converted_files:
                    print(f"  ✓ {c}")
                    if c.endswith('.xlsx'):
                        xlsx_output_path = c
        except Exception as e:
            print(f"[ERROR] Conversion failed: {e}")

        # Handle evaluation(s). Metric scripts read JSON natively (same
        # contract as ``tools/run_metrics.py``), so we always have an
        # extraction file to feed them — no XLSX gate. Prefer xlsx when the
        # user converted to it (legacy paths still work); otherwise pass
        # the JSON we just wrote.
        metric_start = time.time()
        metric_duration = 0
        if args.evaluation_methods and args.baseline_path:
            extraction_path = (xlsx_output_path
                               if xlsx_output_path and os.path.isfile(xlsx_output_path)
                               else output_file)
            methods = expand_evaluation_methods(args.evaluation_methods)
            if 'entity' not in methods:
                methods.append('entity')
            methods = [m for m in ALL_METHODS_ORDER if m in methods]
            for method in methods:
                run_evaluation_method(args, extraction_path, method)
            metric_duration = time.time() - metric_start


        real_end_time = time.time()
        run_stats = {
            'start_time': real_start_time,
            'end_time': real_end_time,
            'duration': real_end_time - real_start_time,
            'total_chunks': total_chunks,
            'total_vulns': after_consolidation_count,
            'metric_duration': metric_duration,
        }
        timing_report = [
            {
                'chunks': total_chunks,
                'vulns': len(all_vulnerabilities),
                'metric_time': metric_duration,
                'total_time': real_end_time - real_start_time,
            }
        ]
        if not args.run_experiments:
            from src.utils.reporting import generate_final_report
            generate_final_report(
                start_time=real_start_time,
                end_time=real_end_time,
                run_stats=run_stats,
                tokens_dir='results_tokens',
                report_dir=os.path.dirname(output_file) or '.',
                include_metrics_time=True,
                timing_report=timing_report
            )
        
        total_time = real_end_time - real_start_time
        print("\n" + "="*60)
        print("[PERFORMANCE] EXECUTION SUMMARY")
        print("="*60)
        print(f"Total execution time: {total_time:.2f}s")
        print(f"LLM: {llm_config.get('model')}")
        print(f"Chunks processed: {total_chunks}")
        print(f"Vulnerability pipeline:")
        print(f"  Extracted: {len(all_vulnerabilities)} vulns")
        print(f"  After deduplication: {run_stats['total_vulns']} vulns")
        print(f"  Final (valid & saved): {final_vuln_count} vulns")
        if metric_duration > 0:
            print(f"Metrics evaluation: {metric_duration:.2f}s")
        print("="*60 + "\n")
    else:
        print(f"\n{'='*60}")
        print("[ERROR] Failed to save results")
        print(f"{'='*60}")
        print(f"Output path: {output_file}")
        print(f"{'='*60}\n")


if __name__ == "__main__":
    main()