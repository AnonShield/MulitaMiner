"""
PDF Vulnerability Extractor - Main Entry Point

Extrai vulnerabilidades de relatórios PDF (OpenVAS/Tenable WAS) usando LLM
e converte para formatos estruturados (JSON/CSV/XLSX).

Usage:
    python main.py --input <caminho_pdf> [--llm <model>] [--convert <format>] [--scanner <name>]
"""
import os
from src.utils.block_creation import create_session_blocks_from_text, extract_vulns_from_blocks, cleanup_temp_blocks

import os
import sys

# Garante que o diretório 'src' esteja no sys.path para imports absolutos
project_root = os.path.abspath(os.path.dirname(__file__))
src_path = os.path.join(project_root, 'src')
if src_path not in sys.path:
    sys.path.insert(0, src_path)


import argparse
import json
import subprocess
import datetime
import time
import glob
import shutil
from tqdm import tqdm
from src.utils.cli_args import parse_arguments
src_path = os.path.join(project_root, 'src')
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from src.utils.cli_args import parse_arguments

# Force UTF-8 encoding on Windows
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')



from src.utils.llm_utils import (
    load_profile, load_llm, init_llm, validate_and_normalize_vulnerability
)
from src.converters import execute_conversions
from src.utils.cais_validator import validate_cais_vulnerability
from src.utils.pdf_loader import load_pdf_with_pypdf2, save_visual_layout
from src.utils.chunking import get_token_based_chunks, retry_chunk_with_subdivision
from src.scanner_strategies.consolidation import central_custom_allow_duplicates
from src.utils.profile_registry import is_cais_profile


def get_validator(profile_config: dict):
    """Obter validador apropriado baseado no perfil."""
    if is_cais_profile(profile_config):
        return validate_cais_vulnerability
    return validate_and_normalize_vulnerability


def validate_inputs(args: argparse.Namespace) -> bool:
    """Valida inputs do usuário."""
    if not os.path.isfile(args.input):
        print(f"❌ Error: PDF file not found: {args.input}")
        return False
    # Validação para o modo de avaliação
    if args.evaluate:
        if not args.baseline:
            print("❌ Error: The --baseline argument is required when --evaluate is used.")
            return False
        if not os.path.isfile(args.baseline):
            print(f"❌ Error: Baseline file not found: {args.baseline}")
            return False
        if args.convert not in ['xlsx', 'all']:
            print("⚠️ Warning: For evaluation, conversion to '.xlsx' is required. Enabling conversion to 'all'.")
            args.convert = 'all'
    return True


def load_configs(args: argparse.Namespace) -> tuple:
    """Carrega configurações de perfil e LLM."""
    profile_config = load_profile(args.scanner)
    if not profile_config:
        print(f"❌ Error loading profile: {args.scanner}")
        return None, None
    llm_config = load_llm(args.llm)
    if not llm_config:
        print(f"❌ Error loading LLM: {args.llm}")
        return None, None
    return profile_config, llm_config


def process_vulnerabilities(doc_texts: list, llm, profile_config: dict) -> list:
    """
    Processa todos os chunks e extrai vulnerabilidades.
    
    Args:
        doc_texts: Lista de chunks de documento
        llm: Instância do LLM inicializada
        profile_config: Configuração do perfil
    
    Returns:
        Lista de todas as vulnerabilidades extraídas
    """
    all_vulnerabilities = []
    max_retries = profile_config.get('retry_attempts', 3)
    total_chunks = len(doc_texts)
    
    with tqdm(total=total_chunks, desc="Processing chunks", unit="chunk", ncols=80) as pbar:
      for i, doc_chunk in enumerate(doc_texts):
        tqdm.write(f"\n{'='*60}")
        tqdm.write(f"🔹 Processing chunk {i+1}/{total_chunks}")
        tqdm.write(f"{'='*60}")
        try:
            vulns_chunk = retry_chunk_with_subdivision(doc_chunk, llm, profile_config, max_retries)
            if vulns_chunk:
                validator = get_validator(profile_config)
                validated_vulns = []
                for v in vulns_chunk:
                    validated = validator(v)
                    if validated:
                        validated_vulns.append(validated)
                name_field = get_consolidation_field(validated_vulns, profile_config)
                all_vulnerabilities.extend(validated_vulns)
                names = [v.get(name_field) for v in validated_vulns if isinstance(v, dict) and v.get(name_field)]
                tqdm.write(f"✅ [CHUNK {i+1}] {len(validated_vulns)}/{len(vulns_chunk)} valid vulnerabilities extracted.")
                if names:
                    tqdm.write(f"   📋 Extracted Names:")
                    for idx, name in enumerate(names, 1):
                        tqdm.write(f"     {idx:2d}. {name}")
            else:
                tqdm.write(f"⚠️ [CHUNK {i+1}] No vulnerabilities extracted.")
        except Exception as e:
            error_msg = str(e).lower()
            if any(kw in error_msg for kw in ['quota', '429', 'rate limit', 'timeout', 'connection']):
                tqdm.write(f"\n🛑 [CRITICAL ERROR] {type(e).__name__}: {str(e)[:200]}")
                tqdm.write(f"⏹️ Stopping processing at chunk {i+1}/{total_chunks}")
                break
            else:
                tqdm.write(f"\n❌ [ERROR] {type(e).__name__}: {str(e)[:200]}")
                tqdm.write(f"➡️  Continuing with next chunk...")
        pbar.update(1)
    return all_vulnerabilities


def save_results(vulnerabilities: list, output_file: str, profile_config: dict = None, allow_duplicates: bool = False) -> dict:
    """
    Salva vulnerabilidades em JSON.
    
    Args:
        vulnerabilities: Lista de vulnerabilidades
        output_file: Caminho do arquivo de saída
        profile_config: Configuração do perfil (opcional)
    
    Returns:
        Dict com status e contagens: {'success': bool, 'extracted': int, 'after_consolidation': int, 'final': int}
    """
    try:

        print(f"\n[PROCESSING] Consolidating vulnerabilities (allow_duplicates={allow_duplicates})")
        final_vulns = central_custom_allow_duplicates(vulnerabilities, profile_config, allow_duplicates, output_file=output_file)
        # Summary of found vulnerabilities
        after_consolidation_count = len(final_vulns) if final_vulns else 0
        if final_vulns:
            print(f"\n[EXTRACTION] Total vulnerabilities found: {len(final_vulns)}")
        else:
            print(f"\n[EXTRACTION] No vulnerabilities found.")
        # Filter vulnerabilities without valid description before saving
        def has_valid_description(vuln):
            desc = vuln.get("description")
            if not desc:
                return False
            if isinstance(desc, list):
                return any(str(d).strip() for d in desc)
            return bool(str(desc).strip())

        removed_vulns = [v for v in final_vulns if not has_valid_description(v)]
        final_vulns = [v for v in final_vulns if has_valid_description(v)]
        # Salva log das vulnerabilidades removidas
        if removed_vulns:
            log_path = os.path.splitext(output_file)[0] + '_removed_log.txt'
            with open(log_path, 'w', encoding='utf-8') as logf:
                logf.write(
                    "# VULNERABILITY REMOVAL LOG\n"
                    "This file lists all vulnerabilities removed due to lack of valid description.\n"
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
                logf.write(f"Final summary: {len(removed_vulns)} vulnerabilities removed due to lack of valid description.\n")
            print(f"[REMOVED] Invalid entries filtered: {len(removed_vulns)}")
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(final_vulns, f, indent=2, ensure_ascii=False)
        
        # Print attractive summary
        print("\n" + "="*60)
        print("[SUMMARY] EXTRACTION COMPLETE")
        print("="*60)
        print(f"✓ Output file: {output_file}")
        print(f"✓ Final vulnerabilities: {len(final_vulns)}")
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
        print(f"❌ Error saving JSON: {e}")
        return {
            'success': False,
            'extracted': len(vulnerabilities) if vulnerabilities else 0,
            'after_consolidation': 0,
            'final': 0
        }


def run_evaluation(args: argparse.Namespace, extraction_output_path: str):
    """
    Executa o script de avaliação de métricas como um processo separado.
    
    Args:
        args: Argumentos da linha de comando, contendo --baseline e --evaluation-method.
        extraction_output_path: Caminho para o arquivo .xlsx gerado pela extração.
    """
    print(f"\n{'='*60}")
    print(f"[METRICS] Evaluating with: {args.evaluation_method.upper()}")
    print(f"{'='*60}")

    method = args.evaluation_method
    script_path = os.path.join('metrics', method, f'compare_extractions_{method}.py')

    if not os.path.isfile(script_path):
        print(f"Error: Evaluation script not found at '{script_path}'")
        return

    # O diretório de saída será relativo ao script de métricas
    output_dir = os.path.join('metrics', method, 'results')

    command = [
        sys.executable,  # Usa o mesmo interpretador Python que está executando o main
        script_path,
        '--baseline-file', args.baseline,
        '--extraction-file', extraction_output_path,
        '--output-dir', output_dir
    ]
    # Passa o nome do modelo explicitamente se disponível
    if hasattr(args, 'llm') and args.llm:
        command += ['--model', args.llm]

    # Passa configuração de duplicatas se especificada
    if hasattr(args, 'allow_duplicates') and args.allow_duplicates:
        command += ['--allow-duplicates']

    try:
        # print(f"[EXEC] Running: {' '.join(command)}")
        subprocess.run(command, check=True)
        print(f"[METRICS] Evaluation completed successfully")
        print(f"[METRICS] Results: {output_dir}")
    except FileNotFoundError:
        print(f"[ERROR] Python or script not found: {script_path}")
        print("Check if the 'metrics' virtual environment is properly configured.")
    except subprocess.CalledProcessError as e:
        print("[ERROR] Metrics evaluation failed")
        print(f"  Command: {' '.join(e.cmd)}")
        print(f"  Exit Code: {e.returncode}")
        print("-------------------------------------------------")


def main():
    """Fluxo principal de extração."""
    # Parse e validação
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--run-experiments', action='store_true', help='Indica execução em lote via run_experiments.py')
    known_args, _ = parser.parse_known_args()
    args = parse_arguments()
    args.run_experiments = getattr(known_args, 'run_experiments', False)
    # Debug info only in verbose mode (currently commented out)
    # print(f"[DEBUG] main.py received arguments: {sys.argv}")
    # print(f"[DEBUG] Namespace args: {args}")
    if not validate_inputs(args):
        return
    real_start_time = time.time()
    
    # Carregar configs
    profile_config, llm_config = load_configs(args)
    if not profile_config or not llm_config:
        return
    
    # Inicializar LLM
    llm = init_llm(llm_config)
    
    # Obter max_tokens (suportar tanto max_tokens quanto max_completion_tokens)
    if 'max_completion_tokens' in llm_config:
        max_tokens = llm_config.get('max_completion_tokens', 4096)
    else:
        max_tokens = llm_config.get('max_tokens', 4096)
    
    # Garantir que max_tokens é um inteiro
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
    
    # Carregamento do PDF em blocos (um Document por página)
    documents = load_pdf_with_pypdf2(args.input)
    if not documents:
        print("Error: Failed to load PDF")
        return

    # Salvar layout visual da primeira página como referência
    visual_file = save_visual_layout(documents[0].page_content, args.input)
    print(f"[LAYOUT] Visual layout saved: {visual_file}")



    # Novo fluxo: gerar texto completo de extração
    extraction_text = ''
    for doc in documents:
        if doc.metadata.get("extraction_method") == "pdfplumber_visual_EXTRACTION":
            extraction_text += doc.page_content + '\n'

    # Criar blocos de sessão temporários
    session_blocks = create_session_blocks_from_text(
        extraction_text,
        temp_dir='temp_blocks',
        visual_layout_path=visual_file,
        scanner=args.scanner
    )
    print(f"[BLOCKS] {len(session_blocks)} session blocks created")

    # Processar cada bloco com chunking e extração, propagando contexto
    all_vulnerabilities = extract_vulns_from_blocks(
        session_blocks, llm, profile_config, get_token_based_chunks
    )
    total_chunks = len(session_blocks)

    # Limpeza obrigatória dos temporários
    cleanup_temp_blocks('temp_blocks')

    print(f"\n{'-'*60}")
    print(f"[EXTRACTION] Total blocks processed: {total_chunks}")
    print(f"[EXTRACTION] Total vulnerabilities found: {len(all_vulnerabilities)}")
    print(f"{'-'*60}")

    # Definir prefixo dos arquivos de saída
    run_prefix = os.environ.get("RUN_PREFIX")
    if args.output_file:
        # Usa exatamente o nome definido pelo usuário, sem timestamp/id
        output_dir = getattr(args, 'output_dir', None) or '.'
        base_name = args.output_file
        if not base_name.endswith('.json'):
            base_name += '.json'
        output_file = os.path.join(output_dir, base_name)
        merge_log_file = output_file.replace('.json', '_merge_log.txt')
        removed_log_file = output_file.replace('.json', '_removed_log.txt')
        xlsx_file = output_file.replace('.json', '.xlsx')
    else:
        pdf_base = os.path.splitext(os.path.basename(args.input))[0]
        llm_name = getattr(args, 'LLM', None) or llm_config.get('model', 'unknown')
        llm_name = str(llm_name).replace('/', '_').replace(':', '_')
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        if getattr(args, 'run_experiments', False) or run_prefix:
            output_dir = getattr(args, 'output_dir', None) or 'results_runs'
            if not os.path.exists(output_dir):
                os.makedirs(output_dir, exist_ok=True)
            prefix = run_prefix if run_prefix else f"{pdf_base}_{llm_name}_{timestamp}"
            output_file = os.path.join(output_dir, f"{prefix}.json")
            merge_log_file = os.path.join(output_dir, f"{prefix}_merge_log.txt")
            removed_log_file = os.path.join(output_dir, f"{prefix}_removed_log.txt")
            xlsx_file = os.path.join(output_dir, f"{prefix}.xlsx")
        else:
            # Não cria results_runs, salva tudo na raiz
            output_dir = '.'
            output_file = f"{pdf_base}_{llm_name}_{timestamp}.json"
            merge_log_file = f"{pdf_base}_{llm_name}_{timestamp}_merge_log.txt"
            removed_log_file = f"{pdf_base}_{llm_name}_{timestamp}_removed_log.txt"
            xlsx_file = f"{pdf_base}_{llm_name}_{timestamp}.xlsx"

    save_result = save_results(all_vulnerabilities, output_file, profile_config, getattr(args, 'allow_duplicates', False))
    # Initialize counts from save_results
    extracted_count = save_result['extracted']
    after_consolidation_count = save_result['after_consolidation']
    final_vuln_count = save_result['final']
    
    xlsx_output_path = None
    
    if save_result['success']:
        os.makedirs('results_tokens', exist_ok=True)
        pid = os.getpid()
        tokens_candidates = glob.glob(f'results_tokens/tokens_info_{pid}.json')
        if tokens_candidates:
            llm_name = getattr(args, 'LLM', None) or llm_config.get('model', 'unknown')
            llm_name = str(llm_name).replace('/', '_').replace(':', '_')
            tokens_final = os.path.join(
                'results_tokens',
                os.path.splitext(os.path.basename(output_file))[0] + f'_{llm_name}_tokens.json'
            )
            shutil.move(tokens_candidates[0], tokens_final)
            print(f"[TOKENS] Token file saved at: {tokens_final}")
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
        metric_start = time.time()
        metric_duration = 0
        if args.evaluate:
            if xlsx_output_path and os.path.isfile(xlsx_output_path):
                run_evaluation(args, xlsx_output_path)
                metric_duration = time.time() - metric_start
            else:
                pass  # Metrics evaluation skipped
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
        # Gera relatório final apenas se não estiver rodando em modo experimentos
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
        
        # Print performance summary
        total_time = real_end_time - real_start_time
        print("\n" + "="*60)
        print("[PERFORMANCE] EXECUTION SUMMARY")
        print("="*60)
        print(f"Total execution time: {total_time:.2f}s")
        print(f"Scanner: {args.scanner.upper()}")
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