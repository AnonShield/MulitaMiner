"""End-to-end extraction: input PDF -> blocks -> chunks -> LLM -> JSON.

The full-pipeline path. ``cli.main`` handles arg parsing, validation and the
metrics-only short-circuit, then calls :func:`run_extraction`.
"""
import argparse
import datetime
import glob
import os
import shutil
import time

from mulitaminer.utils.block_creation import (
    create_session_blocks_from_text,
    extract_vulns_from_blocks,
    cleanup_temp_blocks,
)
from mulitaminer.readers import get_reader
from mulitaminer.utils.chunking import get_token_based_chunks
from mulitaminer.llm import load_profile, load_llm, init_llm
from mulitaminer.writers import execute_conversions
from mulitaminer.configs.constants import TMP_DIR, TOKENS_DIR, DEBUG_DIR
from mulitaminer.pipeline.save import save_results
from mulitaminer.pipeline.metrics_dispatch import (
    expand_evaluation_methods,
    run_evaluation_method,
    ALL_METHODS_ORDER,
)


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


def run_extraction(args: argparse.Namespace) -> None:
    """Run the full extraction pipeline for a single input."""
    real_start_time = time.time()

    # Contexto p/ o log de usage REAL (outputs/tokens/usage_real_*.jsonl):
    # grava o baseline (target) e o run no registro -> custo real por baseline sem depender de PID.
    try:
        if getattr(args, 'input', None):
            os.environ['MULITA_TARGET'] = os.path.splitext(os.path.basename(args.input))[0]
        if getattr(args, 'output_file', None):
            os.environ['MULITA_RUN'] = args.output_file
    except Exception:
        pass

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

    # Load the input via the format-appropriate reader (PDF/CSV/...).
    print(f"[INPUT] Loading: {args.input}")
    try:
        reader = get_reader(args.input)
    except ValueError as e:
        print(f"[ERROR] {e}")
        return

    doc = reader.read(
        args.input, scanner=args.scanner, output_dir=args.output_dir,
        use_markdown=getattr(args, 'use_markdown', False),
    )
    if doc is None:
        print("[ERROR] No text could be extracted from the input.")
        return

    output_ext = doc.output_ext
    visual_file = doc.visual_layout_path
    print(f"[LAYOUT] Visual layout: {visual_file}")

    extraction_text = doc.text

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
    temp_dir = str(TMP_DIR / f'temp_blocks_{unique_process_id}')
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
    debug_dir = getattr(args, 'debug_dir', str(DEBUG_DIR))

    all_vulnerabilities = extract_vulns_from_blocks(
        session_blocks, llm, profile_config, get_token_based_chunks, llm_config=llm_config,
        pdf_name=pdf_name, llm_name=llm_name, debug_mode=debug_mode
    )
    total_chunks = len(session_blocks)

    cleanup_temp_blocks(temp_dir=temp_dir)

    print(f"\n{'-'*60}")
    print(f"[EXTRACTION] Total blocks processed: {total_chunks}")
    print(f"{'-'*60}")

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
        tokens_candidates = glob.glob(os.path.join(str(TOKENS_DIR), f'tokens_info_{pid}.json'))
        if tokens_candidates:
            llm_name = llm_config.get('model', 'unknown').replace('/', '_').replace(':', '_')
            tokens_final_name = f"{output_base}_{llm_name}_tokens.json"
            tokens_final_path = os.path.join(str(TOKENS_DIR), tokens_final_name)

            # Ensure the directory exists
            os.makedirs(TOKENS_DIR, exist_ok=True)

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
            from mulitaminer.utils.reporting import generate_final_report
            generate_final_report(
                start_time=real_start_time,
                end_time=real_end_time,
                run_stats=run_stats,
                tokens_dir=str(TOKENS_DIR),
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
